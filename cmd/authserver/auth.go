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

type authResult struct {
	Authorized bool
	Renewed    bool
	RuleScope  string
	RuleID     string
	RuleType   string
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
			log.WithFields(log.Fields{
				"event":     "auth_expired",
				"source_ip": k.IP,
				"client_id": k.ClientID,
				"port":      cfg.BindPort,
				"result":    "expired",
			}).Infof("authed client %s to port %d was expired", k.IP, cfg.BindPort)
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

func isIPMatchRules(ip net.IP, rules []accessRule) bool {
	for _, r := range rules {
		value := r.resolvedValue
		if value == "" && r.IP != "" {
			value = r.IP
		}
		if isIPMatchRule(ip, value) {
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

func matchTokenRules(token string, scope string, rules []accessRule) (authResult, bool) {
	for i, r := range rules {
		value := r.resolvedValue
		ruleID := r.ruleID
		ruleType := r.ruleType
		if value == "" && r.Token != "" {
			value = r.Token
			ruleID = inlineRuleID(scope, 0, "token", i+1)
			ruleType = "inline_token"
		}
		if glob.Glob(value, token) {
			return authResult{
				Authorized: true,
				RuleScope:  scope,
				RuleID:     ruleID,
				RuleType:   ruleType,
			}, true
		}
	}
	return authResult{}, false
}

func authClient(req utils.AuthConfig, ip string) bool {
	return authorizeClient(ip, "", req.Port, req.Token).Authorized
}

func authorizeClient(ip string, clientID string, port uint16, token string) authResult {
	for i := range globalConfig.ForwardConfigs {
		cfg := &globalConfig.ForwardConfigs[i]
		if cfg.BindPort != port {
			continue
		}
		result, ok := matchTokenRules(token, "global", globalConfig.GlobalAllowTokens)
		if !ok {
			result, ok = matchTokenRules(token, "forward", cfg.AllowTokens)
		}
		if ok {
			muxClient.Lock()
			key := authorizedClientKey{IP: ip, ClientID: clientID}
			list := allClientList[cfg]
			now := time.Now()
			cleanupAuthorizedClientList(list, now)
			_, exists := list[key]
			if !exists && maxAuthorizedClients > 0 && len(list) >= maxAuthorizedClients {
				muxClient.Unlock()
				return authResult{}
			}
			list[key] = authorizedClientState{ExpiresAt: now.Add(time.Second * time.Duration(*cfg.AuthExpiredTime))}
			muxClient.Unlock()
			result.Renewed = exists
			return result
		}
	}
	return authResult{}
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
	result := authorizeClient(peer.IP.String(), resp.ClientID, resp.Port, resp.Token)
	if result.Authorized {
		fields := log.Fields{
			"event":      "auth_success",
			"source_ip":  peer.IP.String(),
			"client_id":  resp.ClientID,
			"key_id":     env.KeyID,
			"port":       resp.Port,
			"result":     "success",
			"rule_scope": result.RuleScope,
			"rule_id":    result.RuleID,
			"rule_type":  result.RuleType,
		}
		if result.Renewed {
			fields["event"] = "auth_renewed"
			fields["result"] = "renewed"
			log.WithFields(fields).Debugf("Auth IP %v renewed to port %d", peer.IP, resp.Port)
		} else {
			log.WithFields(fields).Infof("Auth IP %v to port %d", peer.IP, resp.Port)
		}
	} else {
		log.WithFields(log.Fields{
			"event":     "auth_failed",
			"source_ip": peer.IP.String(),
			"client_id": resp.ClientID,
			"key_id":    env.KeyID,
			"port":      resp.Port,
			"result":    "failed",
			"reason":    "token_or_port_not_allowed",
		}).Warnf("Auth IP %v failed: port %d", peer.IP, resp.Port)
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
