package main

import "testing"

func TestClientConfigRejectsUnsafeAuthSettings(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "missing client id",
			cfg: config{Servers: []serverConfig{{
				Addr: "127.0.0.1:40100",
				Key:  "abcdefghijklmnopqrstuvwxyz123456",
				AuthConfigs: []authConfig{{
					Token: "token-abcdefghijklmnopqrstuvwxyz",
					Port:  40022,
				}},
			}}},
		},
		{
			name: "server address missing port",
			cfg: config{ClientID: "workstation", Servers: []serverConfig{{
				Addr: "127.0.0.1",
				Key:  "abcdefghijklmnopqrstuvwxyz123456",
				AuthConfigs: []authConfig{{
					Token: "token-abcdefghijklmnopqrstuvwxyz",
					Port:  40022,
				}},
			}}},
		},
		{
			name: "weak key",
			cfg: config{ClientID: "workstation", Servers: []serverConfig{{
				Addr: "127.0.0.1:40100",
				Key:  "a safe key",
				AuthConfigs: []authConfig{{
					Token: "token-abcdefghijklmnopqrstuvwxyz",
					Port:  40022,
				}},
			}}},
		},
		{
			name: "weak token",
			cfg: config{ClientID: "workstation", Servers: []serverConfig{{
				Addr: "127.0.0.1:40100",
				Key:  "abcdefghijklmnopqrstuvwxyz123456",
				AuthConfigs: []authConfig{{
					Token: "admin",
					Port:  40022,
				}},
			}}},
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

func TestClientConfigAcceptsConfirmedSSHMigrationConfig(t *testing.T) {
	cfg := config{
		ClientID: "workstation",
		LogLevel: "info",
		Servers: []serverConfig{{
			Addr: "127.0.0.1:40100",
			Key:  "abcdefghijklmnopqrstuvwxyz123456",
			AuthConfigs: []authConfig{{
				Token: "token-abcdefghijklmnopqrstuvwxyz",
				Port:  40022,
			}},
		}},
	}
	if err := cfg.CheckValid(); err != nil {
		t.Fatalf("expected config to be valid: %v", err)
	}
}

func TestClientTemplateRequiresReplacingSecrets(t *testing.T) {
	if _, err := readConfig("config.yaml.template"); err == nil {
		t.Fatal("expected template config to be rejected until secrets are replaced")
	}
}
