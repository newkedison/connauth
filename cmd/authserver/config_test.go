package main

import (
	"testing"

	"connauth/utils"
)

func TestServerConfigRejectsUnsafeAuthSettings(t *testing.T) {
	expiry := uint32(60)
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "missing server id",
			cfg: config{
				AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
				ForwardConfigs: []forwardConfig{{
					BindPort:        40022,
					ForwardAddr:     "127.0.0.1:22",
					AllowTokens:     []string{"abcdefghijklmnopqrstuvwxyz123456"},
					AuthExpiredTime: &expiry,
				}},
			},
		},
		{
			name: "weak auth key",
			cfg: config{
				ServerID: "connauth-server",
				AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "a safe key"}},
				ForwardConfigs: []forwardConfig{{
					BindPort:        40022,
					ForwardAddr:     "127.0.0.1:22",
					AllowTokens:     []string{"abcdefghijklmnopqrstuvwxyz123456"},
					AuthExpiredTime: &expiry,
				}},
			},
		},
		{
			name: "weak token",
			cfg: config{
				ServerID: "connauth-server",
				AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
				ForwardConfigs: []forwardConfig{{
					BindPort:        40022,
					ForwardAddr:     "127.0.0.1:22",
					AllowTokens:     []string{"admin"},
					AuthExpiredTime: &expiry,
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.CheckValid(); err == nil {
				t.Fatal("expected config to be rejected")
			}
		})
	}
}

func TestServerConfigAcceptsConfirmedSSHMigrationConfig(t *testing.T) {
	expiry := uint32(60)
	cfg := config{
		ServerID: "connauth-server",
		LogLevel: "info",
		AuthAddr: "0.0.0.0:40100",
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []string{"token-abcdefghijklmnopqrstuvwxyz"},
			AuthExpiredTime: &expiry,
		}},
	}
	if err := cfg.CheckValid(); err != nil {
		t.Fatalf("expected config to be valid: %v", err)
	}
}

func TestServerTemplateRequiresReplacingSecrets(t *testing.T) {
	if _, err := readConfig("config.yaml.template"); err == nil {
		t.Fatal("expected template config to be rejected until secrets are replaced")
	}
}

func TestServerConfigValidatesAuthKeys(t *testing.T) {
	expiry := uint32(60)
	base := config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []string{"token-abcdefghijklmnopqrstuvwxyz"},
			AuthExpiredTime: &expiry,
		}},
	}
	tests := []struct {
		name string
		keys []authKeyConfig
	}{
		{
			name: "duplicate key id",
			keys: []authKeyConfig{
				{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"},
				{ID: "primary-2026-06", Key: "zyxwvutsrqponmlkjihgfedcba654321"},
			},
		},
		{
			name: "not yet valid key",
			keys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456", NotBefore: "2999-01-01T00:00:00Z"}},
		},
		{
			name: "expired key",
			keys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456", NotAfter: "2000-01-01T00:00:00Z"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.AuthKeys = tt.keys
			if err := cfg.CheckValid(); err == nil {
				t.Fatal("expected auth key config to be rejected")
			}
		})
	}
}

func TestServerConfigAllowsTokenRotationWindow(t *testing.T) {
	expiry := uint32(60)
	cfg := config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens: []string{
				"old-token-abcdefghijklmnopqrstuvwxyz",
				"new-token-abcdefghijklmnopqrstuvwxyz",
			},
			AuthExpiredTime: &expiry,
		}},
	}
	if err := cfg.CheckValid(); err != nil {
		t.Fatalf("expected token rotation config to be valid: %v", err)
	}
	globalConfig = &cfg
	initClientList()
	if !authClient(*newAuthRequestForTest("old-token-abcdefghijklmnopqrstuvwxyz", 40022), "192.0.2.10") {
		t.Fatal("expected old token to auth during rotation window")
	}
	if !authClient(*newAuthRequestForTest("new-token-abcdefghijklmnopqrstuvwxyz", 40022), "192.0.2.11") {
		t.Fatal("expected new token to auth during rotation window")
	}
}

func TestServerConfigRejectsWildcardGlobalToken(t *testing.T) {
	cfg := config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
		GlobalAllowTokens: []string{"*"},
	}
	if err := cfg.CheckValid(); err == nil {
		t.Fatal("expected wildcard global token to be rejected")
	}
}

func newAuthRequestForTest(token string, port uint16) *utils.AuthRequest {
	return utils.NewAuthRequest(token, port)
}
