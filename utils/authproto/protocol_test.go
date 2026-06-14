package authproto

import (
	"testing"
	"time"
)

func TestChallengeRequestValidation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	req := ChallengeRequest{
		Type:        MessageTypeChallengeRequest,
		ServerID:    "connauth-server",
		ClientID:    "workstation",
		Port:        40022,
		ClientNonce: "client-nonce",
		Timestamp:   now.Unix(),
	}
	if err := req.Validate(now); err != nil {
		t.Fatalf("expected request to be valid: %v", err)
	}

	req.ServerID = ""
	if err := req.Validate(now); err == nil {
		t.Fatal("expected empty server id to fail")
	}
}

func TestChallengeResponseValidation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	resp := ChallengeResponse{
		Type:        MessageTypeChallengeResponse,
		ServerID:    "connauth-server",
		ClientID:    "workstation",
		Port:        40022,
		ClientNonce: "client-nonce",
		ServerNonce: "server-nonce",
		Token:       "token-abcdefghijklmnopqrstuvwxyz",
		Timestamp:   now.Unix(),
	}
	if err := resp.Validate(now); err != nil {
		t.Fatalf("expected response to be valid: %v", err)
	}

	resp.Token = ""
	if err := resp.Validate(now); err == nil {
		t.Fatal("expected empty token to fail")
	}
}

func TestTimestampAllowedRejectsStaleAndFutureValues(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if !TimestampAllowed(now.Unix(), now) {
		t.Fatal("expected current timestamp to be allowed")
	}
	if TimestampAllowed(now.Add(-MaxPastSkew-time.Second).Unix(), now) {
		t.Fatal("expected stale timestamp to be rejected")
	}
	if TimestampAllowed(now.Add(MaxFutureSkew+time.Second).Unix(), now) {
		t.Fatal("expected future timestamp to be rejected")
	}
}

func TestEnvelopeValidation(t *testing.T) {
	env := Envelope{
		KeyID:    "primary-2026-06",
		ServerID: "connauth-server",
		Payload:  []byte("payload"),
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("expected envelope to be valid: %v", err)
	}
	env.Payload = nil
	if err := env.Validate(); err == nil {
		t.Fatal("expected empty payload to fail")
	}
}
