package main

import (
	"connauth/utils"
	"encoding/json"
	"fmt"
	"github.com/ryanuber/go-glob"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

var allClientList map[*forwardConfig]map[string]time.Time

func refreshClientList(cfg *forwardConfig) {
	list := allClientList[cfg]
	if len(list) == 0 {
		return
	}
	now := time.Now()
	for k, v := range list {
		if v.Before(now) {
			log.Infof("authed client %s to port %d was expired", k, cfg.BindPort)
			delete(list, k)
		}
	}
}

func isIPMatchRule(ip net.IP, rule string) bool {
	log.Debugf("check if %s match %s", ip.String(), rule)
	if rule == "" {
		return false
	}
	sIP := ip.String()
	if sIP == rule {
		return true
	}
	if _, subNet, err := net.ParseCIDR(rule); err != nil {
		return false
	} else {
		return subNet.Contains(ip)
	}
}

func isIPMatchRules(ip net.IP, rules []string) bool {
	for _, r := range rules {
		if isIPMatchRule(ip, r) {
			return true
		}
	}
	return false
}

func isIPAuthed(cfg *forwardConfig, ip net.IP) bool {
	if isIPMatchRules(ip, globalConfig.GlobalDenyIPs) {
		return false
	}
	if isIPMatchRules(ip, globalConfig.GlobalAllowIPs) {
		return true
	}
	if isIPMatchRules(ip, cfg.AllowIPs) {
		return true
	}
	list := allClientList[cfg]
	if _, ok := list[ip.String()]; ok {
		return true
	}
	return false
}

func isTokenMatchRules(token string, rules []string) bool {
	for _, r := range rules {
		if glob.Glob(r, token) {
			return true
		}
	}
	return false
}

func authClient(req utils.AuthRequest, ip string) bool {
	for i := range globalConfig.ForwardConfigs {
		cfg := &globalConfig.ForwardConfigs[i]
		if cfg.BindPort != req.Port {
			continue
		}
		if isTokenMatchRules(req.Token, globalConfig.GlobalAllowTokens) ||
			isTokenMatchRules(req.Token, cfg.AllowTokens) {
			log.Infof("accept token %s for port %d, ip: %s",
				req.Token, req.Port, ip)
			allClientList[cfg][ip] =
				time.Now().Add(time.Second * time.Duration(*cfg.AuthExpiredTime))
			return true
		}
	}
	return false
}

func waitForAuth(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve authaddr %s failed: %v", addr, err)
	}
	authWaiter, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind to authaddr %s failed: %v", addr, err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := authWaiter.ReadFromUDP(buf)
			if err != nil {
				log.Warnf("read from auth addr %s failed: %v", addr, err)
				continue
			}
			if n == 0 {
				continue
			}
			var request utils.AuthRequest
			if err := json.Unmarshal(buf[:n], &request); err != nil {
				continue
			}
			if !request.IsValid() {
				continue
			}
			if authClient(request, peer.IP.String()) {
				log.Infof("Auth IP %v to port %d with token %s",
					peer.IP, request.Port, request.Token)
			} else {
				log.Warnf("Auth IP %v failed: port %d token %s",
					peer.IP, request.Port, request.Token)
			}
		}
	}()
	return nil
}

func initClientList() {
	allClientList = make(map[*forwardConfig]map[string]time.Time)
	for i := range globalConfig.ForwardConfigs {
		allClientList[&globalConfig.ForwardConfigs[i]] = make(map[string]time.Time)
	}
}
