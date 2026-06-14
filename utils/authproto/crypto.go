package authproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const protocolAADPrefix = "connauth:challenge-auth"

func additionalData(ctx Context) []byte {
	return []byte(protocolAADPrefix + ":" + ctx.KeyID + ":" + ctx.ServerID)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	cipherKey := sha256.Sum256(key)
	block, err := aes.NewCipher(cipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm failed: %v", err)
	}
	return gcm, nil
}

func Seal(key []byte, ctx Context, plain []byte) ([]byte, error) {
	if err := validateField("key_id", ctx.KeyID); err != nil {
		return nil, err
	}
	if err := validateField("server_id", ctx.ServerID); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce failed: %v", err)
	}
	return gcm.Seal(nonce, nonce, plain, additionalData(ctx)), nil
}

func Open(key []byte, ctx Context, sealed []byte) ([]byte, error) {
	if err := validateField("key_id", ctx.KeyID); err != nil {
		return nil, err
	}
	if err := validateField("server_id", ctx.ServerID); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext invalid")
	}
	nonce, text := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, text, additionalData(ctx))
	if err != nil {
		return nil, fmt.Errorf("decrypt failed")
	}
	return plain, nil
}

func RandomNonceString() (string, error) {
	buf := make([]byte, NonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate nonce failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
