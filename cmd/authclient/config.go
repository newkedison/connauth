package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"strings"
	"unicode"
)

var globalConfig *config

// const value
const (
	DefaultConfigFile = "client_config.yaml"
)

func newUint32(x uint32) *uint32 {
	return &x
}

type serverConfig struct {
	Addr        string
	ServerID    string
	KeyID       string
	Key         string
	AuthConfigs []authConfig
}

func (c *serverConfig) CheckValid() error {
	if c.Addr == "" {
		return fmt.Errorf("addr cannot be empty")
	}
	if c.Key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	if err := validateIdentifier("serverid", c.ServerID); err != nil {
		return err
	}
	if err := validateIdentifier("keyid", c.KeyID); err != nil {
		return err
	}
	if err := validateSecret("key", c.Key); err != nil {
		return err
	}
	if _, err := net.ResolveUDPAddr("udp", c.Addr); err != nil {
		return fmt.Errorf("cannot resolve addr %s: %v", c.Addr, err)
	}
	for i := range c.AuthConfigs {
		if err := c.AuthConfigs[i].CheckValid(); err != nil {
			return fmt.Errorf("authconfig %d invalid: %v", i+1, err)
		} else {
			c.AuthConfigs[i].SetDefaultValue()
		}
	}
	return nil
}

type authConfig struct {
	Token string
	Port  uint16
	// re-auth interval by second, not less then 10, can be omit, default: 60
	Interval *uint32
}

func (c *authConfig) CheckValid() error {
	if c.Token == "" {
		return fmt.Errorf("token cannot be empty")
	}
	if err := validateSecret("token", c.Token); err != nil {
		return err
	}
	if c.Port == 0 {
		return fmt.Errorf("port cannot be empty")
	}
	if c.Interval != nil && *c.Interval < 10 {
		return fmt.Errorf("interval must not less then 10")
	}
	return nil
}

func (c *authConfig) SetDefaultValue() {
	if c.Interval == nil {
		c.Interval = newUint32(60)
	}
}

type config struct {
	ClientID string
	LogLevel string
	Service  struct {
		ServiceName string
		DisplayName string
		Description string
	}
	Servers []serverConfig
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
	if err := validateIdentifier("clientid", c.ClientID); err != nil {
		return err
	}
	for i := range c.Servers {
		if err := c.Servers[i].CheckValid(); err != nil {
			return fmt.Errorf("server %d invalid: %v", i+1, err)
		}
	}
	return nil
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
	if err := c.CheckValid(); err != nil {
		return nil, err
	}

	return c, nil
}
