package main

import (
	"io/ioutil"
	"path/filepath"
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
					AllowTokens:     []accessRule{{Token: "abcdefghijklmnopqrstuvwxyz123456"}},
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
					AllowTokens:     []accessRule{{Token: "abcdefghijklmnopqrstuvwxyz123456"}},
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
					AllowTokens:     []accessRule{{Token: "admin"}},
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
			AllowTokens:     []accessRule{{Token: "token-abcdefghijklmnopqrstuvwxyz"}},
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
			AllowTokens:     []accessRule{{Token: "token-abcdefghijklmnopqrstuvwxyz"}},
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
			AllowTokens:     []accessRule{{Token: "old-token-abcdefghijklmnopqrstuvwxyz"}, {Token: "new-token-abcdefghijklmnopqrstuvwxyz"}},
			AuthExpiredTime: &expiry,
		}},
	}
	if err := cfg.CheckValid(); err != nil {
		t.Fatalf("expected token rotation config to be valid: %v", err)
	}
	globalConfig = &cfg
	initClientList()
	if !authClient(*newAuthConfigForTest("old-token-abcdefghijklmnopqrstuvwxyz", 40022), "192.0.2.10") {
		t.Fatal("expected old token to auth during rotation window")
	}
	if !authClient(*newAuthConfigForTest("new-token-abcdefghijklmnopqrstuvwxyz", 40022), "192.0.2.11") {
		t.Fatal("expected new token to auth during rotation window")
	}
}

func TestServerConfigResolvesTokenAndIPReferences(t *testing.T) {
	expiry := uint32(60)
	cfg := config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
		Tokens: map[string]string{
			"ssh-primary": "token-abcdefghijklmnopqrstuvwxyz",
		},
		IPRules: map[string]string{
			"office-primary": "198.51.100.10",
		},
		GlobalAllowIPs: []accessRule{{IPRef: "office-primary"}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{TokenRef: "ssh-primary"}, {Token: "inline-token-abcdefghijklmnopqrstuvwxyz"}},
			AllowIPs:        []accessRule{{IPRef: "office-primary"}, {IP: "192.0.2.10"}},
			AuthExpiredTime: &expiry,
		}},
	}
	if err := cfg.CheckValid(); err != nil {
		t.Fatalf("expected ref config to be valid: %v", err)
	}
	if cfg.ForwardConfigs[0].AllowTokens[0].resolvedValue != "token-abcdefghijklmnopqrstuvwxyz" ||
		cfg.ForwardConfigs[0].AllowTokens[0].ruleID != "ssh-primary" ||
		cfg.ForwardConfigs[0].AllowTokens[1].ruleID != "inline:forward:40022:token:2" {
		t.Fatalf("unexpected resolved token rules: %#v", cfg.ForwardConfigs[0].AllowTokens)
	}
	if cfg.GlobalAllowIPs[0].resolvedValue != "198.51.100.10" ||
		cfg.GlobalAllowIPs[0].ruleID != "office-primary" ||
		cfg.ForwardConfigs[0].AllowIPs[1].ruleID != "inline:forward:40022:ip:2" {
		t.Fatalf("unexpected resolved ip rules: global=%#v forward=%#v", cfg.GlobalAllowIPs, cfg.ForwardConfigs[0].AllowIPs)
	}
}

func TestServerConfigRejectsUnknownRuleReferences(t *testing.T) {
	expiry := uint32(60)
	cfg := config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{TokenRef: "missing-token"}},
			AuthExpiredTime: &expiry,
		}},
	}
	if err := cfg.CheckValid(); err == nil {
		t.Fatal("expected unknown token ref to be rejected")
	}
}

func TestServerConfigRejectsWildcardGlobalToken(t *testing.T) {
	cfg := config{
		ServerID:          "connauth-server",
		AuthAddr:          "127.0.0.1:40100",
		AuthKeys:          []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
		GlobalAllowTokens: []accessRule{{Token: "*"}},
	}
	if err := cfg.CheckValid(); err == nil {
		t.Fatal("expected wildcard global token to be rejected")
	}
}

func TestServerConfigRejectsIncompleteEnabledSLS(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "server.yaml")
	content := []byte(`
serverid: "connauth-server"
authaddr: "127.0.0.1:40100"
authkeys:
  - id: "primary-2026-06"
    key: "abcdefghijklmnopqrstuvwxyz123456"
forwardconfigs:
  - bindport: 40022
    forwardaddr: "127.0.0.1:22"
    allowtokens:
      - "token-abcdefghijklmnopqrstuvwxyz"
logger:
  aliyunsls:
    enabled: true
`)
	if err := ioutil.WriteFile(cfgFile, content, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := readConfig(cfgFile); err == nil {
		t.Fatal("expected incomplete enabled SLS config to fail")
	}
}

func newAuthConfigForTest(token string, port uint16) *utils.AuthConfig {
	return utils.NewAuthConfig(token, port)
}
