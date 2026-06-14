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

type authorizedClientKey struct {
	IP       string
	ClientID string
}

type authorizedClientState struct {
	ExpiresAt time.Time
}

var allClientList map[*forwardConfig]map[authorizedClientKey]authorizedClientState
var muxClient sync.Mutex
var pendingChallenges = newPendingChallengeStore(10000, 16)
var maxAuthorizedClients = 10000

func refreshClientList(cfg *forwardConfig) {
	muxClient.Lock()
	defer muxClient.Unlock()
	list := allClientList[cfg]
	if len(list) == 0 {
		return
	}
	now := time.Now()
	for k, v := range list {
		if !v.ExpiresAt.After(now) {
			log.Infof("authed client %s to port %d was expired", k.IP, cfg.BindPort)
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
	if isIPDenied(ip) {
		return false
	}
	if isStaticIPAllowed(cfg, ip) {
		return true
	}
	muxClient.Lock()
	defer muxClient.Unlock()
	list := allClientList[cfg]
	now := time.Now()
	for key, state := range list {
		if key.IP != ip.String() {
			continue
		}
		if state.ExpiresAt.After(now) {
			return true
		}
		delete(list, key)
	}
	return false
}

func isClientAuthed(cfg *forwardConfig, ip net.IP, clientID string) bool {
	if isIPDenied(ip) {
		return false
	}
	if isStaticIPAllowed(cfg, ip) {
		return true
	}
	muxClient.Lock()
	defer muxClient.Unlock()
	list := allClientList[cfg]
	key := authorizedClientKey{IP: ip.String(), ClientID: clientID}
	state, ok := list[key]
	if !ok {
		return false
	}
	if !state.ExpiresAt.After(time.Now()) {
		delete(list, key)
		return false
	}
	return true
}

func isStaticIPAllowed(cfg *forwardConfig, ip net.IP) bool {
	if isIPMatchRules(ip, globalConfig.GlobalAllowIPs) {
		return true
	}
	if isIPMatchRules(ip, cfg.AllowIPs) {
		return true
	}
	return false
}

func isIPDenied(ip net.IP) bool {
	return isIPMatchRules(ip, globalConfig.GlobalDenyIPs)
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
	return authorizeClient(ip, "", req.Port, req.Token)
}

func authorizeClient(ip string, clientID string, port uint16, token string) bool {
	for i := range globalConfig.ForwardConfigs {
		cfg := &globalConfig.ForwardConfigs[i]
		if cfg.BindPort != port {
			continue
		}
		if isTokenMatchRules(token, globalConfig.GlobalAllowTokens) ||
			isTokenMatchRules(token, cfg.AllowTokens) {
			muxClient.Lock()
			key := authorizedClientKey{IP: ip, ClientID: clientID}
			list := allClientList[cfg]
			cleanupAuthorizedClientList(list, time.Now())
			if _, exists := list[key]; !exists && maxAuthorizedClients > 0 && len(list) >= maxAuthorizedClients {
				muxClient.Unlock()
				return false
			}
			list[key] = authorizedClientState{ExpiresAt: time.Now().Add(time.Second * time.Duration(*cfg.AuthExpiredTime))}
			muxClient.Unlock()
			return true
		}
	}
	return false
}

func cleanupAuthorizedClientList(list map[authorizedClientKey]authorizedClientState, now time.Time) {
	for key, state := range list {
		if !state.ExpiresAt.After(now) {
			delete(list, key)
		}
	}
}

func waitForAuth(addr string, stop <-chan struct{}) (<-chan struct{}, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve authaddr %s failed: %v", addr, err)
	}
	authWaiter, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind to authaddr %s failed: %v", addr, err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-stop
		_ = authWaiter.Close()
	}()
	go func() {
		defer wg.Done()
		for {
			buf := make([]byte, 4096)
			n, peer, err := authWaiter.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
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
		defer wg.Done()
		ticker := time.NewTicker(time.Second * 60)
		defer ticker.Stop()
		for {
			deleted := pendingChallenges.cleanup(time.Now())
			log.Debugf("pending challenge count delete: %d", deleted)
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(done)
	}()
	return done, nil
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
	if authorizeClient(peer.IP.String(), resp.ClientID, resp.Port, resp.Token) {
		log.Infof("Auth IP %v to port %d", peer.IP, resp.Port)
	} else {
		log.Warnf("Auth IP %v failed: port %d", peer.IP, resp.Port)
	}
}

func initClientList() {
	muxClient.Lock()
	defer muxClient.Unlock()
	allClientList = make(map[*forwardConfig]map[authorizedClientKey]authorizedClientState)
	for i := range globalConfig.ForwardConfigs {
		allClientList[&globalConfig.ForwardConfigs[i]] = make(map[authorizedClientKey]authorizedClientState)
	}
}
