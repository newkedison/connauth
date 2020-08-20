package main

import (
	"fmt"
	"io/ioutil"
	"net"

	yaml "gopkg.in/yaml.v2"
)

var globalConfig *config

// const value
const (
	DefaultConfigFile         = "config.yaml"
	DefaultRedisLoggerMaxSize = 0
)

func newUint32(x uint32) *uint32 {
	return &x
}

type authRule struct {
	Token           string   // support wildcast
	AlwaysAllowIPs  []string // white list of IP addresses of this token, support CIDR notation, these IPs will never expired, default: empty
	AuthExpiredTime *uint32  // auto delete temporary auth IP after N seconds, 0 for not delete, default: 3600
}

func (r *authRule) CheckValid() error {
	if r.Token == "" {
		return fmt.Errorf("token cannot be empty")
	}
	return nil
}

func (r *authRule) SetDefaultValue() {
	if r.AuthExpiredTime == nil {
		r.AuthExpiredTime = newUint32(3600)
	}
}

type forwardConfig struct {
	BindAddr      string     // listening address, eg: 0.0.0.0:80
	ForwardAddr   string     // address of read backend, eg: 127.0.0.1:8080
	AllowRules    []authRule // empty means DENY ALL
	DropDelayTime *uint32    // milliseconds before close an unauth connection, 0 for close immediately, default: 0
	MaxConnection *uint32    // maximum auth connection, reject new connection if current connection exceed this limitation, 0 for no limitation, defautl: 0
}

func (c *forwardConfig) CheckValid() error {
	if c.BindAddr == "" || c.ForwardAddr == "" {
		return fmt.Errorf("bindaddr and forwardaddr cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.BindAddr); err != nil {
		return fmt.Errorf("bindaddr is invalid %v", err)
	}
	if _, _, err := net.SplitHostPort(c.ForwardAddr); err != nil {
		return fmt.Errorf("forwardaddr is invalid %v", err)
	}
	for i := range c.AllowRules {
		if err := c.AllowRules[i].CheckValid(); err != nil {
			return fmt.Errorf("allowrules %d invalid: %v", i+1, err)
		}
	}
	return nil
}

func (c *forwardConfig) SetDefaultValue() {
	if c.DropDelayTime == nil {
		c.DropDelayTime = newUint32(0)
	}
	if c.MaxConnection == nil {
		c.MaxConnection = newUint32(0)
	}
}

type config struct {
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
	ForwardConfigs   []forwardConfig
	GlobalAllowRules []authRule // add to all ForwardConfigs
	DenyIPs          []string   // black list of IP addresses to connect to any port, support CIDR notation
}

func readConfig(fileName string) (*config, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	c := &config{}
	err = yaml.Unmarshal(content, c)
	if err != nil {
		return nil, fmt.Errorf("Parse config file %s fail: %v", fileName, err)
	}
	if c.RedisLogger.Enabled {
		if c.RedisLogger.Addr == "" {
			return nil, fmt.Errorf("Must provide the address of redis server")
		}
		if c.RedisLogger.Port < 1 || c.RedisLogger.Port > 65534 {
			return nil, fmt.Errorf("Invalid redis server port.")
		}
		if c.RedisLogger.Key == "" {
			return nil, fmt.Errorf("Must provide a list key in redis")
		}
		if c.RedisLogger.DB < 0 || c.RedisLogger.DB > 15 {
			return nil, fmt.Errorf("Invalid redis DB")
		}
		if c.RedisLogger.MaxSize < 0 {
			c.RedisLogger.MaxSize = 0
		}
	}
	for i := range c.ForwardConfigs {
		if err := c.ForwardConfigs[i].CheckValid(); err != nil {
			return nil, fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
		} else {
			c.ForwardConfigs[i].SetDefaultValue()
		}
	}
	for i := range c.GlobalAllowRules {
		if err := c.GlobalAllowRules[i].CheckValid(); err != nil {
			return nil, fmt.Errorf("globalconfigs %d error: %v", i+1, err)
		} else {
			c.GlobalAllowRules[i].SetDefaultValue()
		}
	}

	return c, nil
}
