package main

import "testing"

func TestServerConfigRejectsUnsafeAuthSettings(t *testing.T) {
	expiry := uint32(60)
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "missing server id",
			cfg: config{
				AuthKey: "abcdefghijklmnopqrstuvwxyz123456",
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
				AuthKey:  "a safe key",
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
				AuthKey:  "abcdefghijklmnopqrstuvwxyz123456",
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
		AuthKey:  "abcdefghijklmnopqrstuvwxyz123456",
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
