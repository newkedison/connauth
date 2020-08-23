package main

import (
	"connauth/utils"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/ryanuber/go-glob"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
)

var allClientList map[*forwardConfig]map[string]time.Time
var allNonce sync.Map
var muxClient sync.Mutex

func refreshClientList(cfg *forwardConfig) {
	muxClient.Lock()
	defer muxClient.Unlock()
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

func deleteOldNonce() {
	deleteCount := 0
	now := time.Now().Unix()
	allNonce.Range(func(key, value interface{}) bool {
		v := value.(int64)
		// delete nonce received one hour ago
		if v < now && (now-v) > 60 {
			allNonce.Delete(key)
			deleteCount++
		}
		return true
	})
	log.Errorf("nonce count delete: %d", deleteCount)
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
	muxClient.Lock()
	defer muxClient.Unlock()
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
			muxClient.Lock()
			allClientList[cfg][ip] =
				time.Now().Add(time.Second * time.Duration(*cfg.AuthExpiredTime))
			muxClient.Unlock()
			return true
		}
	}
	return false
}

func decrypt(buf []byte, key []byte) ([]byte, error) {
	if len(buf) == 0 || len(key) == 0 {
		return nil, fmt.Errorf("decrypt fail: %d %d", len(buf), len(key))
	}
	var cipherKey [32]byte
	cipherKey = sha256.Sum256(key)
	c, err := aes.NewCipher(cipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher fail: %v", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("make GCM fail: %v", err)
	}
	if len(buf) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext invalid")
	}
	nonce, text := buf[:gcm.NonceSize()], buf[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, text, []byte(utils.AdditionalData))
	if err != nil {
		return nil, fmt.Errorf("gcm.Open fail: %v", err)
	}
	return plain, nil
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
		for {
			buf := make([]byte, 4096)
			n, peer, err := authWaiter.ReadFromUDP(buf)
			if err != nil {
				log.Warnf("read from auth addr %s failed: %v", addr, err)
				continue
			}
			if n == 0 {
				continue
			}
			if buf, err = decrypt(buf[:n], []byte(globalConfig.AuthKey)); err != nil {
				log.Infof("decrypt data from %s failed: %v", peer.String(), err)
				if len(buf) >= n {
					log.Debug(spew.Sdump(buf[:n]))
				}
				continue
			}
			var request utils.AuthRequest
			if err := json.Unmarshal(buf, &request); err != nil {
				log.Warnf("unmarshal request failed: %v", err)
				continue
			}
			if !request.IsValid() {
				log.Warnf("request invalid")
				continue
			}
			now := time.Now().Unix()
			if request.Timestamp < now-300 || request.Timestamp > now+60 {
				log.Warnf("timestamp of client was error: %d %d", request.Timestamp, now)
				continue
			}
			if _, ok := allNonce.Load(request.Nonce); ok {
				log.Errorf("[ATTACK]duplicate nonce from %s", peer.String())
				continue
			}
			allNonce.Store(request.Nonce, now)
			if authClient(request, peer.IP.String()) {
				log.Infof("Auth IP %v to port %d with token %s",
					peer.IP, request.Port, request.Token)
			} else {
				log.Warnf("Auth IP %v failed: port %d token %s",
					peer.IP, request.Port, request.Token)
			}
		}
	}()
	go func() {
		for {
			deleteOldNonce()
			time.Sleep(time.Second * 60)
		}
	}()
	return nil
}

func initClientList() {
	muxClient.Lock()
	defer muxClient.Unlock()
	allClientList = make(map[*forwardConfig]map[string]time.Time)
	for i := range globalConfig.ForwardConfigs {
		allClientList[&globalConfig.ForwardConfigs[i]] = make(map[string]time.Time)
	}
}
