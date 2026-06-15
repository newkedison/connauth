package authproto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := []byte("abcdefghijklmnopqrstuvwxyz123456")
	plain := []byte(`{"type":"challenge_request"}`)
	ctx := Context{KeyID: "primary-2026-06", ServerID: "connauth-server"}

	sealed, err := Seal(key, ctx, plain)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	opened, err := Open(key, ctx, sealed)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("opened plaintext mismatch: %s", opened)
	}
}

func TestOpenRejectsWrongKeyAADAndTampering(t *testing.T) {
	ctx := Context{KeyID: "primary-2026-06", ServerID: "connauth-server"}
	sealed, err := Seal([]byte("abcdefghijklmnopqrstuvwxyz123456"), ctx, []byte("secret"))
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	if _, err := Open([]byte("wrong-abcdefghijklmnopqrstuvwxyz"), ctx, sealed); err == nil {
		t.Fatal("expected wrong key to fail")
	}
	wrongCtx := Context{KeyID: "primary-2026-06", ServerID: "other-server"}
	if _, err := Open([]byte("abcdefghijklmnopqrstuvwxyz123456"), wrongCtx, sealed); err == nil {
		t.Fatal("expected wrong aad to fail")
	}
	sealed[len(sealed)-1] ^= 0x01
	if _, err := Open([]byte("abcdefghijklmnopqrstuvwxyz123456"), ctx, sealed); err == nil {
		t.Fatal("expected tampering to fail")
	}
}

func TestRandomNonceStringIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		nonce, err := RandomNonceString()
		if err != nil {
			t.Fatalf("nonce generation failed: %v", err)
		}
		if seen[nonce] {
			t.Fatalf("duplicate nonce generated: %s", nonce)
		}
		seen[nonce] = true
	}
}
