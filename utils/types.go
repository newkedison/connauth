package utils

import "time"

type AuthConfig struct {
	Token     string
	Port      uint16
	Timestamp int64
	Nonce     string
}

func (r AuthConfig) IsValid() bool {
	return r.Token != "" && r.Port != 0
}

func NewAuthConfig(token string, port uint16) *AuthConfig {
	return &AuthConfig{
		Token:     token,
		Port:      port,
		Timestamp: time.Now().Unix(),
	}
}
