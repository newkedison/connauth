package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
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
	LogLevel string
	Service  struct {
		ServiceName string
		DisplayName string
		Description string
	}
	Servers []serverConfig
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
	for i := range c.Servers {
		if err := c.Servers[i].CheckValid(); err != nil {
			return nil, fmt.Errorf("server %d invalid: %v", i+1, err)
		}
	}

	return c, nil
}
