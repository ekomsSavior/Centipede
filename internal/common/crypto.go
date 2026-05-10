package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
