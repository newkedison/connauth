package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v2"
)

var globalConfig *config

// const value
const (
	DefaultConfigFile = "server_config.yaml"
)

func newUint32(x uint32) *uint32 {
	return &x
}

type forwardConfig struct {
	BindPort        uint16   // listening port, eg: 80, will bind to all interfaces
	ForwardAddr     string   // address of real backend, eg: 127.0.0.1:8080
	AllowTokens     []string // client can be auth by tokens list here, use asterisk(*) for wildcard, default: empty
	AllowIPs        []string // IP white list that can always connect and never expired, support CIDR notation, default: empty
	DropDelayTime   *uint32  // milliseconds before close an unauth connection, 0 for close immediately, default: 0
	AuthExpiredTime *uint32  // seconds before an auth by token is expired, default 3600
}

func (c *forwardConfig) CheckValid() error {
	if c.ForwardAddr == "" {
		return fmt.Errorf("authaddr and forwardaddr cannot be empty")
	}
	if c.BindPort == 0 || c.BindPort == 65535 {
		return fmt.Errorf("bindport allow range 1~65534")
	}
	if _, _, err := net.SplitHostPort(c.ForwardAddr); err != nil {
		return fmt.Errorf("forwardaddr is invalid %v", err)
	}
	for _, ip := range c.AllowIPs {
		if _, err := net.ResolveIPAddr("ip", ip); err != nil {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("allowips has invalid ip: %s", ip)
			}
		}
	}
	return nil
}

func (c *forwardConfig) SetDefaultValue() {
	if c.DropDelayTime == nil {
		c.DropDelayTime = newUint32(0)
	}
	if c.AuthExpiredTime == nil {
		c.AuthExpiredTime = newUint32(3600)
	}
}

type config struct {
	ServerID string
	LogLevel string
	Service  struct {
		ServiceName string
		DisplayName string
		Description string
	}
	RedisLogger struct {
		Enabled  bool
		Addr     string
		Port     int
		Password string
		Key      string
		DB       int
		MaxSize  int
	}
	AuthAddr          string // UDP addr for auth by token
	AuthKeys          []authKeyConfig
	ForwardConfigs    []forwardConfig
	GlobalAllowTokens []string // use asterisk(*) for wildcard
	GlobalAllowIPs    []string // add to all ForwardConfigs
	GlobalDenyIPs     []string // black list of IP addresses to connect to any port, support CIDR notation
}

type authKeyConfig struct {
	ID        string
	Key       string
	NotBefore string
	NotAfter  string
}

func (c *authKeyConfig) CheckValid(now time.Time) error {
	if err := validateIdentifier("key id", c.ID); err != nil {
		return err
	}
	if err := validateSecret("authkey", c.Key); err != nil {
		return err
	}
	if c.NotBefore != "" {
		t, err := time.Parse(time.RFC3339, c.NotBefore)
		if err != nil {
			return fmt.Errorf("notbefore invalid: %v", err)
		}
		if now.Before(t) {
			return fmt.Errorf("authkey %s is not active yet", c.ID)
		}
	}
	if c.NotAfter != "" {
		t, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			return fmt.Errorf("notafter invalid: %v", err)
		}
		if !now.Before(t) {
			return fmt.Errorf("authkey %s is expired", c.ID)
		}
	}
	return nil
}

func validateIdentifier(kind string, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", kind)
	}
	if len(value) > 64 {
		return fmt.Errorf("%s too long", kind)
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("%s contains invalid character", kind)
	}
	return nil
}

func isWeakSecret(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 24 {
		return true
	}
	switch s {
	case "a safe key", "admin", "valid_token", "global_token", "change_me":
		return true
	}
	return strings.Contains(s, "change_me")
}

func validateSecret(kind string, value string) error {
	if isWeakSecret(value) {
		return fmt.Errorf("%s is empty, too short, or uses an unsafe example value", kind)
	}
	return nil
}

func (c *config) CheckValid() error {
	if err := validateIdentifier("serverid", c.ServerID); err != nil {
		return err
	}
	if _, err := net.ResolveUDPAddr("udp", c.AuthAddr); err != nil {
		return fmt.Errorf("authaddr is invalid: %v", err)
	}
	if len(c.AuthKeys) == 0 {
		return fmt.Errorf("authkeys cannot be empty")
	}
	seenKeys := map[string]bool{}
	now := time.Now()
	for i := range c.AuthKeys {
		if err := c.AuthKeys[i].CheckValid(now); err != nil {
			return fmt.Errorf("authkeys %d error: %v", i+1, err)
		}
		if seenKeys[c.AuthKeys[i].ID] {
			return fmt.Errorf("duplicate authkey id %s", c.AuthKeys[i].ID)
		}
		seenKeys[c.AuthKeys[i].ID] = true
	}
	for _, token := range c.GlobalAllowTokens {
		if token == "*" {
			return fmt.Errorf("globalallowtokens cannot contain wildcard *")
		}
		if err := validateSecret("global allow token", token); err != nil {
			return err
		}
	}
	for i := range c.ForwardConfigs {
		if err := c.ForwardConfigs[i].CheckValid(); err != nil {
			return fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
		}
		for _, token := range c.ForwardConfigs[i].AllowTokens {
			if token == "*" {
				return fmt.Errorf("forwardconfigs %d allowtokens cannot contain wildcard *", i+1)
			}
			if err := validateSecret("allow token", token); err != nil {
				return fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
			}
		}
		c.ForwardConfigs[i].SetDefaultValue()
	}
	return nil
}

func (c *config) activeAuthKey() string {
	if len(c.AuthKeys) == 0 {
		return ""
	}
	return c.AuthKeys[0].Key
}

func (c *config) authKeyByID(keyID string) (string, bool) {
	now := time.Now()
	for _, key := range c.AuthKeys {
		if key.ID != keyID {
			continue
		}
		if key.NotBefore != "" {
			t, err := time.Parse(time.RFC3339, key.NotBefore)
			if err != nil || now.Before(t) {
				return "", false
			}
		}
		if key.NotAfter != "" {
			t, err := time.Parse(time.RFC3339, key.NotAfter)
			if err != nil || !now.Before(t) {
				return "", false
			}
		}
		return key.Key, true
	}
	return "", false
}

func readConfig(fileName string) (*config, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	c := &config{}
	err = yaml.Unmarshal(content, c)
	if err != nil {
		return nil, fmt.Errorf("parse config file %s fail: %v", fileName, err)
	}
	if c.RedisLogger.Enabled {
		if c.RedisLogger.Addr == "" {
			return nil, fmt.Errorf("must provide the address of redis server")
		}
		if c.RedisLogger.Port < 1 || c.RedisLogger.Port > 65534 {
			return nil, fmt.Errorf("invalid redis server port")
		}
		if c.RedisLogger.Key == "" {
			return nil, fmt.Errorf("must provide a list key in redis")
		}
		if c.RedisLogger.DB < 0 || c.RedisLogger.DB > 15 {
			return nil, fmt.Errorf("invalid redis DB")
		}
		if c.RedisLogger.MaxSize < 0 {
			c.RedisLogger.MaxSize = 0
		}
	}
	if err := c.CheckValid(); err != nil {
		return nil, err
	}

	return c, nil
}
