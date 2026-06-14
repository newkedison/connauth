package authproto

import (
	"fmt"
	"time"
)

const (
	MessageTypeChallengeRequest  = "challenge_request"
	MessageTypeChallenge         = "challenge"
	MessageTypeChallengeResponse = "challenge_response"
)

const (
	MaxPastSkew   = 60 * time.Second
	MaxFutureSkew = 15 * time.Second
	ChallengeTTL  = 30 * time.Second
	NonceBytes    = 32
	MaxPacketSize = 4096
	MaxFieldSize  = 128
)

type Context struct {
	KeyID    string
	ServerID string
}

type Envelope struct {
	KeyID    string `json:"key_id"`
	ServerID string `json:"server_id"`
	Payload  []byte `json:"payload"`
}

type ChallengeRequest struct {
	Type        string `json:"type"`
	ServerID    string `json:"server_id"`
	ClientID    string `json:"client_id"`
	Port        uint16 `json:"port"`
	ClientNonce string `json:"client_nonce"`
	Timestamp   int64  `json:"timestamp"`
}

type Challenge struct {
	Type        string `json:"type"`
	ServerID    string `json:"server_id"`
	ClientID    string `json:"client_id"`
	Port        uint16 `json:"port"`
	ClientNonce string `json:"client_nonce"`
	ServerNonce string `json:"server_nonce"`
	ExpiresAt   int64  `json:"expires_at"`
}

type ChallengeResponse struct {
	Type        string `json:"type"`
	ServerID    string `json:"server_id"`
	ClientID    string `json:"client_id"`
	Port        uint16 `json:"port"`
	ClientNonce string `json:"client_nonce"`
	ServerNonce string `json:"server_nonce"`
	Token       string `json:"token"`
	Timestamp   int64  `json:"timestamp"`
}

func TimestampAllowed(ts int64, now time.Time) bool {
	msgTime := time.Unix(ts, 0)
	return !msgTime.Before(now.Add(-MaxPastSkew)) && !msgTime.After(now.Add(MaxFutureSkew))
}

func validateField(name string, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", name)
	}
	if len(value) > MaxFieldSize {
		return fmt.Errorf("%s too long", name)
	}
	return nil
}

func validateBase(msgType string, serverID string, clientID string, port uint16, timestamp int64, now time.Time) error {
	if err := validateField("type", msgType); err != nil {
		return err
	}
	if err := validateField("server_id", serverID); err != nil {
		return err
	}
	if err := validateField("client_id", clientID); err != nil {
		return err
	}
	if port == 0 {
		return fmt.Errorf("port cannot be empty")
	}
	if !TimestampAllowed(timestamp, now) {
		return fmt.Errorf("timestamp outside allowed window")
	}
	return nil
}

func (e Envelope) Validate() error {
	if err := validateField("key_id", e.KeyID); err != nil {
		return err
	}
	if err := validateField("server_id", e.ServerID); err != nil {
		return err
	}
	if len(e.Payload) == 0 {
		return fmt.Errorf("payload cannot be empty")
	}
	if len(e.Payload) > MaxPacketSize {
		return fmt.Errorf("payload too large")
	}
	return nil
}

func (m ChallengeRequest) Validate(now time.Time) error {
	if err := validateBase(m.Type, m.ServerID, m.ClientID, m.Port, m.Timestamp, now); err != nil {
		return err
	}
	if m.Type != MessageTypeChallengeRequest {
		return fmt.Errorf("invalid challenge request type")
	}
	return validateField("client_nonce", m.ClientNonce)
}

func (m ChallengeResponse) Validate(now time.Time) error {
	if err := validateBase(m.Type, m.ServerID, m.ClientID, m.Port, m.Timestamp, now); err != nil {
		return err
	}
	if m.Type != MessageTypeChallengeResponse {
		return fmt.Errorf("invalid challenge response type")
	}
	if err := validateField("client_nonce", m.ClientNonce); err != nil {
		return err
	}
	if err := validateField("server_nonce", m.ServerNonce); err != nil {
		return err
	}
	return validateField("token", m.Token)
}
