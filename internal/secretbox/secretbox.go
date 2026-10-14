// Package secretbox encrypts small secrets (SSH passwords, TLS private keys)
// before they are written to the database.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Values written by Seal start with this prefix. Anything without it is
// treated as legacy plaintext so existing rows keep working until migrated.
const sealedPrefix = "enc:v1:"

// KeySize is the required key length in bytes (AES-256).
const KeySize = 32

type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// ParseKey accepts a 32-byte key encoded as base64 (std or URL, padded or not)
// or as 64 hex characters.
func ParseKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("secretbox: key is empty")
	}
	if len(encoded) == hex.EncodedLen(KeySize) {
		if key, err := hex.DecodeString(encoded); err == nil {
			return key, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(encoded); err == nil && len(key) == KeySize {
			return key, nil
		}
	}
	return nil, fmt.Errorf("secretbox: key must be %d bytes encoded as base64 or hex", KeySize)
}

// IsSealed reports whether value was produced by Seal.
func IsSealed(value string) bool {
	return strings.HasPrefix(value, sealedPrefix)
}

// Seal encrypts plaintext. Empty input stays empty so NULL/blank semantics are kept.
func (b *Box) Seal(plaintext string) (string, error) {
	if plaintext == "" || IsSealed(plaintext) {
		return plaintext, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: nonce: %w", err)
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open decrypts a value produced by Seal. Legacy plaintext is returned unchanged.
func (b *Box) Open(stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, sealedPrefix))
	if err != nil {
		return "", fmt.Errorf("secretbox: decode: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns+b.aead.Overhead() {
		return "", errors.New("secretbox: ciphertext too short")
	}
	plain, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", errors.New("secretbox: decryption failed (wrong DATA_ENCRYPTION_KEY?)")
	}
	return string(plain), nil
}
