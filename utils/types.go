package utils

import "time"

type AuthRequest struct {
	Token     string
	Port      uint16
	Timestamp int64
	Nonce     string
}

func (r AuthRequest) IsValid() bool {
	return r.Token != "" && r.Port != 0
}

func NewAuthRequest(token string, port uint16) *AuthRequest {
	return &AuthRequest{
		Token:     token,
		Port:      port,
		Timestamp: time.Now().Unix(),
	}
}
