package main

import (
	"connauth/utils"
	"connauth/utils/authproto"
	"encoding/json"
	"fmt"
	"github.com/ryanuber/go-glob"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
)

var allClientList map[*forwardConfig]map[string]time.Time
var muxClient sync.Mutex
var pendingChallenges = newPendingChallengeStore(10000, 16)

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
			handleAuthPacket(authWaiter, peer, buf[:n])
		}
	}()
	go func() {
		for {
			deleted := pendingChallenges.cleanup(time.Now())
			log.Debugf("pending challenge count delete: %d", deleted)
			time.Sleep(time.Second * 60)
		}
	}()
	return nil
}

func handleAuthPacket(conn *net.UDPConn, peer *net.UDPAddr, packet []byte) {
	var env authproto.Envelope
	if err := json.Unmarshal(packet, &env); err != nil {
		log.Debugf("auth packet from %s ignored: invalid envelope", peer.IP.String())
		return
	}
	if err := env.Validate(); err != nil {
		log.Debugf("auth packet from %s ignored: invalid envelope", peer.IP.String())
		return
	}
	if env.ServerID != globalConfig.ServerID {
		log.Debugf("auth packet from %s ignored: server mismatch", peer.IP.String())
		return
	}
	key, ok := globalConfig.authKeyByID(env.KeyID)
	if !ok {
		log.Debugf("auth packet from %s ignored: unknown key id", peer.IP.String())
		return
	}
	plain, err := authproto.Open([]byte(key), authproto.Context{KeyID: env.KeyID, ServerID: env.ServerID}, env.Payload)
	if err != nil {
		log.Debugf("auth packet from %s ignored: decrypt failed", peer.IP.String())
		return
	}
	var header struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(plain, &header); err != nil {
		log.Debugf("auth packet from %s ignored: invalid payload", peer.IP.String())
		return
	}
	switch header.Type {
	case authproto.MessageTypeChallengeRequest:
		handleChallengeRequest(conn, peer, env, key, plain)
	case authproto.MessageTypeChallengeResponse:
		handleChallengeResponse(peer, env, plain)
	default:
		log.Debugf("auth packet from %s ignored: unknown message type", peer.IP.String())
	}
}

func handleChallengeRequest(conn *net.UDPConn, peer *net.UDPAddr, env authproto.Envelope, key string, plain []byte) {
	var req authproto.ChallengeRequest
	if err := json.Unmarshal(plain, &req); err != nil || req.Validate(time.Now()) != nil {
		log.Debugf("challenge request from %s ignored: invalid request", peer.IP.String())
		return
	}
	if req.ServerID != globalConfig.ServerID {
		log.Debugf("challenge request from %s ignored: server mismatch", peer.IP.String())
		return
	}
	serverNonce, err := authproto.RandomNonceString()
	if err != nil {
		log.Warnf("challenge request from %s ignored: nonce generation failed", peer.IP.String())
		return
	}
	expiresAt := time.Now().Add(authproto.ChallengeTTL)
	pendingKey := pendingChallengeKey{
		IP:          peer.IP.String(),
		KeyID:       env.KeyID,
		ServerID:    req.ServerID,
		ClientID:    req.ClientID,
		Port:        req.Port,
		ClientNonce: req.ClientNonce,
		ServerNonce: serverNonce,
	}
	if !pendingChallenges.add(pendingKey, expiresAt) {
		log.Debugf("challenge request from %s ignored: pending limit reached", peer.IP.String())
		return
	}
	challenge := authproto.Challenge{
		Type:        authproto.MessageTypeChallenge,
		ServerID:    req.ServerID,
		ClientID:    req.ClientID,
		Port:        req.Port,
		ClientNonce: req.ClientNonce,
		ServerNonce: serverNonce,
		ExpiresAt:   expiresAt.Unix(),
	}
	body, err := json.Marshal(challenge)
	if err != nil {
		log.Warnf("challenge request from %s ignored: marshal failed", peer.IP.String())
		return
	}
	sealed, err := authproto.Seal([]byte(key), authproto.Context{KeyID: env.KeyID, ServerID: env.ServerID}, body)
	if err != nil {
		log.Warnf("challenge request from %s ignored: seal failed", peer.IP.String())
		return
	}
	resp, err := json.Marshal(authproto.Envelope{KeyID: env.KeyID, ServerID: env.ServerID, Payload: sealed})
	if err != nil {
		log.Warnf("challenge request from %s ignored: envelope failed", peer.IP.String())
		return
	}
	_, _ = conn.WriteToUDP(resp, peer)
}

func handleChallengeResponse(peer *net.UDPAddr, env authproto.Envelope, plain []byte) {
	var resp authproto.ChallengeResponse
	if err := json.Unmarshal(plain, &resp); err != nil || resp.Validate(time.Now()) != nil {
		log.Debugf("challenge response from %s ignored: invalid response", peer.IP.String())
		return
	}
	key := pendingChallengeKey{
		IP:          peer.IP.String(),
		KeyID:       env.KeyID,
		ServerID:    resp.ServerID,
		ClientID:    resp.ClientID,
		Port:        resp.Port,
		ClientNonce: resp.ClientNonce,
		ServerNonce: resp.ServerNonce,
	}
	if !pendingChallenges.consume(key, time.Now()) {
		log.Debugf("challenge response from %s ignored: no pending challenge", peer.IP.String())
		return
	}
	req := utils.NewAuthRequest(resp.Token, resp.Port)
	if authClient(*req, peer.IP.String()) {
		log.Infof("Auth IP %v to port %d", peer.IP, resp.Port)
	} else {
		log.Warnf("Auth IP %v failed: port %d", peer.IP, resp.Port)
	}
}

func initClientList() {
	muxClient.Lock()
	defer muxClient.Unlock()
	allClientList = make(map[*forwardConfig]map[string]time.Time)
	for i := range globalConfig.ForwardConfigs {
		allClientList[&globalConfig.ForwardConfigs[i]] = make(map[string]time.Time)
	}
}
