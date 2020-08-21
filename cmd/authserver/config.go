package main

import (
	"fmt"
	"io/ioutil"
	"net"

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
	ForwardConfigs    []forwardConfig
	GlobalAllowTokens []string // use asterisk(*) for wildcard
	GlobalAllowIPs    []string // add to all ForwardConfigs
	GlobalDenyIPs     []string // black list of IP addresses to connect to any port, support CIDR notation
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
	for i := range c.ForwardConfigs {
		if err := c.ForwardConfigs[i].CheckValid(); err != nil {
			return nil, fmt.Errorf("forwardconfigs %d error: %v", i+1, err)
		} else {
			c.ForwardConfigs[i].SetDefaultValue()
		}
	}

	return c, nil
}
