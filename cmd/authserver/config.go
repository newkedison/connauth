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
	BindPort        uint16       // listening port, eg: 80, will bind to all interfaces
	ForwardAddr     string       // address of real backend, eg: 127.0.0.1:8080
	AllowTokens     []accessRule // client can be auth by tokens list here, default: empty
	AllowIPs        []accessRule // IP white list that can always connect and never expired, support CIDR notation, default: empty
	DropDelayTime   *uint32      // milliseconds before close an unauth connection, 0 for close immediately, default: 0
	AuthExpiredTime *uint32      // seconds before an auth by token is expired, default 3600
	MaxConnPerIP    *uint32
	MaxConnGlobal   *uint32
	DialTimeoutMS   *uint32
	IdleTimeoutMS   *uint32
}

func (c *forwardConfig) CheckValid() error {
	if c.ForwardAddr == "" {
		return fmt.Errorf("authaddr and forwardaddr cannot be empty")
	}
	if c.BindPort == 0 || c.BindPort == 65535 {
		return fmt.Errorf("bindport allow range 1~65534")
	}
	if c.DropDelayTime != nil && *c.DropDelayTime > 5000 {
		return fmt.Errorf("dropdelaytime must not exceed 5000 ms")
	}
	if _, _, err := net.SplitHostPort(c.ForwardAddr); err != nil {
		return fmt.Errorf("forwardaddr is invalid %v", err)
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
	if c.MaxConnPerIP == nil {
		c.MaxConnPerIP = newUint32(16)
	}
	if c.MaxConnGlobal == nil {
		c.MaxConnGlobal = newUint32(1024)
	}
	if c.DialTimeoutMS == nil {
		c.DialTimeoutMS = newUint32(3000)
	}
	if c.IdleTimeoutMS == nil {
		c.IdleTimeoutMS = newUint32(300000)
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
	Logger struct {
		AliyunSLS struct {
			Enabled         bool
			Endpoint        string
			ProjectName     string
			LogStoreName    string
			Topic           string
			AccessKeyID     string
			AccessKeySecret string
		}
	}
	AuthAddr          string // UDP addr for auth by token
	AuthKeys          []authKeyConfig
	Tokens            map[string]string
	IPRules           map[string]string
	ForwardConfigs    []forwardConfig
	GlobalAllowTokens []accessRule // token rules that can auth any port
	GlobalAllowIPs    []accessRule // add to all ForwardConfigs
	GlobalDenyIPs     []accessRule // black list of IP addresses to connect to any port, support CIDR notation
}

type accessRule struct {
	Token    string
	TokenRef string
	IP       string
	IPRef    string
	Inline   string `yaml:"-"`

	resolvedValue string
	ruleID        string
	ruleType      string
}

func (r *accessRule) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var inline string
	if err := unmarshal(&inline); err == nil {
		r.Inline = inline
		return nil
	}
	type raw accessRule
	var out raw
	if err := unmarshal(&out); err != nil {
		return err
	}
	*r = accessRule(out)
	return nil
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

func validateIPRule(kind string, value string) error {
	if _, err := net.ResolveIPAddr("ip", value); err != nil {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("%s has invalid ip: %s", kind, value)
		}
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
	for id, token := range c.Tokens {
		if err := validateIdentifier("token id", id); err != nil {
			return err
		}
		if token == "*" {
			return fmt.Errorf("token %s cannot contain wildcard *", id)
		}
		if err := validateSecret("token "+id, token); err != nil {
			return err
		}
	}
	for id, rule := range c.IPRules {
		if err := validateIdentifier("ip rule id", id); err != nil {
			return err
		}
		if err := validateIPRule("ip rule "+id, rule); err != nil {
			return err
		}
	}
	if err := c.resolveTokenRules(c.GlobalAllowTokens, "global", 0); err != nil {
		return err
	}
	if err := c.resolveIPRules(c.GlobalAllowIPs, "global", 0); err != nil {
		return err
	}
	if err := c.resolveIPRules(c.GlobalDenyIPs, "global_deny", 0); err != nil {
		return err
	}
	for i := range c.ForwardConfigs {
		if err := c.ForwardConfigs[i].CheckValid(); err != nil {
			return fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
		}
		if err := c.resolveTokenRules(c.ForwardConfigs[i].AllowTokens, "forward", c.ForwardConfigs[i].BindPort); err != nil {
			return fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
		}
		if err := c.resolveIPRules(c.ForwardConfigs[i].AllowIPs, "forward", c.ForwardConfigs[i].BindPort); err != nil {
			return fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
		}
		c.ForwardConfigs[i].SetDefaultValue()
	}
	return nil
}

func (c *config) resolveTokenRules(rules []accessRule, scope string, port uint16) error {
	for i := range rules {
		rule, err := c.resolveTokenRule(rules[i], scope, port, i+1)
		if err != nil {
			return err
		}
		rules[i] = rule
	}
	return nil
}

func (c *config) resolveTokenRule(rule accessRule, scope string, port uint16, index int) (accessRule, error) {
	if rule.TokenRef != "" {
		if rule.Token != "" || rule.IP != "" || rule.IPRef != "" || rule.Inline != "" {
			return rule, fmt.Errorf("tokenref cannot be combined with inline rule")
		}
		value, ok := c.Tokens[rule.TokenRef]
		if !ok {
			return rule, fmt.Errorf("unknown tokenref %s", rule.TokenRef)
		}
		rule.resolvedValue = value
		rule.ruleID = rule.TokenRef
		rule.ruleType = "token_ref"
		return rule, nil
	}
	value := rule.Token
	if value == "" {
		value = rule.Inline
	}
	if value == "" || rule.IP != "" || rule.IPRef != "" {
		return rule, fmt.Errorf("token rule must contain token or tokenref")
	}
	if value == "*" {
		return rule, fmt.Errorf("token rule cannot contain wildcard *")
	}
	if err := validateSecret("token rule", value); err != nil {
		return rule, err
	}
	rule.resolvedValue = value
	rule.ruleID = inlineRuleID(scope, port, "token", index)
	rule.ruleType = "inline_token"
	return rule, nil
}

func (c *config) resolveIPRules(rules []accessRule, scope string, port uint16) error {
	for i := range rules {
		rule, err := c.resolveIPRule(rules[i], scope, port, i+1)
		if err != nil {
			return err
		}
		rules[i] = rule
	}
	return nil
}

func (c *config) resolveIPRule(rule accessRule, scope string, port uint16, index int) (accessRule, error) {
	if rule.IPRef != "" {
		if rule.IP != "" || rule.Token != "" || rule.TokenRef != "" || rule.Inline != "" {
			return rule, fmt.Errorf("ipref cannot be combined with inline rule")
		}
		value, ok := c.IPRules[rule.IPRef]
		if !ok {
			return rule, fmt.Errorf("unknown ipref %s", rule.IPRef)
		}
		rule.resolvedValue = value
		rule.ruleID = rule.IPRef
		rule.ruleType = "ip_ref"
		return rule, nil
	}
	value := rule.IP
	if value == "" {
		value = rule.Inline
	}
	if value == "" || rule.Token != "" || rule.TokenRef != "" {
		return rule, fmt.Errorf("ip rule must contain ip or ipref")
	}
	if err := validateIPRule("ip rule", value); err != nil {
		return rule, err
	}
	rule.resolvedValue = value
	rule.ruleID = inlineRuleID(scope, port, "ip", index)
	rule.ruleType = "inline_ip"
	return rule, nil
}

func inlineRuleID(scope string, port uint16, kind string, index int) string {
	if port == 0 {
		return fmt.Sprintf("inline:%s:%s:%d", scope, kind, index)
	}
	return fmt.Sprintf("inline:%s:%d:%s:%d", scope, port, kind, index)
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
	if c.Logger.AliyunSLS.Enabled {
		if c.Logger.AliyunSLS.Endpoint == "" ||
			c.Logger.AliyunSLS.ProjectName == "" ||
			c.Logger.AliyunSLS.LogStoreName == "" {
			return nil, fmt.Errorf("aliyun sls endpoint, projectname, and logstorename are required")
		}
	}
	if err := c.CheckValid(); err != nil {
		return nil, err
	}

	return c, nil
}
