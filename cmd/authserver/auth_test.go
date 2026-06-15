package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"connauth/utils/authproto"
	log "github.com/sirupsen/logrus"
)

func TestAuthClientDoesNotLogToken(t *testing.T) {
	var buf bytes.Buffer
	previousOut := log.StandardLogger().Out
	previousLevel := log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	defer func() {
		log.SetOutput(previousOut)
		log.SetLevel(previousLevel)
	}()

	token := "super-secret-token"
	authKey := "test-auth-key"
	authAddr := freeUDPAddr(t)
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: authKey}},
		ForwardConfigs: []forwardConfig{
			{
				BindPort:        2222,
				ForwardAddr:     "127.0.0.1:22",
				AllowTokens:     []accessRule{{Token: token}},
				AuthExpiredTime: &expiry,
			},
		},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	time.Sleep(20 * time.Millisecond)
	if err := sendChallengeAuthForTest(authAddr, "primary-2026-06", authKey, "connauth-server", "workstation", token, 2222); err != nil {
		t.Fatalf("send auth request failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	stopAuth()

	if strings.Contains(buf.String(), token) {
		t.Fatalf("log output contains token: %s", buf.String())
	}
}

func TestChallengeRequestRespondsAndResponseSilentlyAuthorizes(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	authKey := "abcdefghijklmnopqrstuvwxyz123456"
	authAddr := freeUDPAddr(t)
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: authKey}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()
	conn := dialUDPForTest(t, authAddr)
	defer conn.Close()

	clientNonce := "client-nonce"
	challenge := sendChallengeRequestForTest(t, conn, authKey, clientNonce, 40022)
	if challenge.ServerNonce == "" {
		t.Fatal("expected server nonce")
	}

	sendChallengeResponseForTest(t, conn, authKey, challenge, token)
	if got := readUDPWithTimeout(conn, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("challenge response must not produce UDP reply, got %d bytes", len(got))
	}
	if !isIPAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("127.0.0.1")) {
		t.Fatal("expected loopback IP to be authorized after challenge response")
	}
}

func TestChallengeRequestWithWrongKeyIsSilent(t *testing.T) {
	authAddr := freeUDPAddr(t)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: "abcdefghijklmnopqrstuvwxyz123456"}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()
	conn := dialUDPForTest(t, authAddr)
	defer conn.Close()

	req := authproto.ChallengeRequest{
		Type:        authproto.MessageTypeChallengeRequest,
		ServerID:    "connauth-server",
		ClientID:    "workstation",
		Port:        40022,
		ClientNonce: "client-nonce",
		Timestamp:   time.Now().Unix(),
	}
	plain, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	sealed, err := authproto.Seal([]byte("wrong-abcdefghijklmnopqrstuvwxyz"), authproto.Context{KeyID: "primary-2026-06", ServerID: "connauth-server"}, plain)
	if err != nil {
		t.Fatalf("seal wrong-key request: %v", err)
	}
	env, err := json.Marshal(authproto.Envelope{KeyID: "primary-2026-06", ServerID: "connauth-server", Payload: sealed})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if _, err := conn.Write(env); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if got := readUDPWithTimeout(conn, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("wrong key request must be silent, got %d bytes", len(got))
	}
}

func TestChallengeRequestWithExpiredRuntimeKeyIsSilent(t *testing.T) {
	authKey := "abcdefghijklmnopqrstuvwxyz123456"
	authAddr := freeUDPAddr(t)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{
			ID:       "primary-2026-06",
			Key:      authKey,
			NotAfter: time.Now().Add(-time.Second).Format(time.RFC3339),
		}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()
	conn := dialUDPForTest(t, authAddr)
	defer conn.Close()

	req := authproto.ChallengeRequest{
		Type:        authproto.MessageTypeChallengeRequest,
		ServerID:    "connauth-server",
		ClientID:    "workstation",
		Port:        40022,
		ClientNonce: "client-nonce",
		Timestamp:   time.Now().Unix(),
	}
	plain, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	sealed, err := authproto.Seal([]byte(authKey), authproto.Context{KeyID: "primary-2026-06", ServerID: "connauth-server"}, plain)
	if err != nil {
		t.Fatalf("seal expired-key request: %v", err)
	}
	env, err := json.Marshal(authproto.Envelope{KeyID: "primary-2026-06", ServerID: "connauth-server", Payload: sealed})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if _, err := conn.Write(env); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if got := readUDPWithTimeout(conn, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("expired key request must be silent, got %d bytes", len(got))
	}
}

func TestChallengeAuthAllowsMultipleActiveKeysDuringRotation(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	oldKey := "old-auth-key-abcdefghijklmnopqrstuvwxyz"
	newKey := "new-auth-key-abcdefghijklmnopqrstuvwxyz"
	authAddr := freeUDPAddr(t)
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{
			{ID: "old-2026-06", Key: oldKey},
			{ID: "new-2026-07", Key: newKey},
		},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()

	if err := sendChallengeAuthForTest(authAddr, "old-2026-06", oldKey, "connauth-server", "old-client", token, 40022); err != nil {
		t.Fatalf("old key auth failed: %v", err)
	}
	if !waitForClientAuthForTest(&globalConfig.ForwardConfigs[0], net.ParseIP("127.0.0.1"), "old-client") {
		t.Fatal("expected old key client to be authorized")
	}
	clearAuthedIPForTest(&globalConfig.ForwardConfigs[0], "127.0.0.1")

	if err := sendChallengeAuthForTest(authAddr, "new-2026-07", newKey, "connauth-server", "new-client", token, 40022); err != nil {
		t.Fatalf("new key auth failed: %v", err)
	}
	if !waitForClientAuthForTest(&globalConfig.ForwardConfigs[0], net.ParseIP("127.0.0.1"), "new-client") {
		t.Fatal("expected new key client to be authorized")
	}
}

func TestChallengeResponseWithWrongTokenIsSilentAndDoesNotAuthorize(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	authKey := "abcdefghijklmnopqrstuvwxyz123456"
	authAddr := freeUDPAddr(t)
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: authKey}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()
	conn := dialUDPForTest(t, authAddr)
	defer conn.Close()

	challenge := sendChallengeRequestForTest(t, conn, authKey, "client-nonce", 40022)
	sendChallengeResponseForTest(t, conn, authKey, challenge, "wrong-token-abcdefghijklmnopqrstuvwxyz")

	if got := readUDPWithTimeout(conn, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("wrong token response must be silent, got %d bytes", len(got))
	}
	if isIPAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("127.0.0.1")) {
		t.Fatal("wrong token must not authorize loopback IP")
	}
}

func TestChallengeRequestForUnknownPortStillReturnsChallenge(t *testing.T) {
	authKey := "abcdefghijklmnopqrstuvwxyz123456"
	authAddr := freeUDPAddr(t)
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: authKey}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: "token-abcdefghijklmnopqrstuvwxyz"}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()
	conn := dialUDPForTest(t, authAddr)
	defer conn.Close()

	challenge := sendChallengeRequestForTest(t, conn, authKey, "client-nonce", 29999)
	if challenge.Port != 29999 {
		t.Fatalf("expected challenge for requested port, got %d", challenge.Port)
	}
}

func TestCapturedChallengeResponseCannotBeReplayed(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	authKey := "abcdefghijklmnopqrstuvwxyz123456"
	authAddr := freeUDPAddr(t)
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: authAddr,
		AuthKeys: []authKeyConfig{{ID: "primary-2026-06", Key: authKey}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	stopAuth := startAuthForTest(t, authAddr)
	defer stopAuth()
	conn := dialUDPForTest(t, authAddr)
	defer conn.Close()

	challenge := sendChallengeRequestForTest(t, conn, authKey, "client-nonce", 40022)
	packet, err := buildChallengeResponsePacket("primary-2026-06", authKey, challenge, token)
	if err != nil {
		t.Fatalf("build challenge response: %v", err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("write first response: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	clearAuthedIPForTest(&globalConfig.ForwardConfigs[0], "127.0.0.1")
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("write replayed response: %v", err)
	}
	if got := readUDPWithTimeout(conn, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("replayed response must be silent, got %d bytes", len(got))
	}
	if isIPAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("127.0.0.1")) {
		t.Fatal("replayed response must not re-authorize loopback IP")
	}
}

func TestAuthorizationStateSeparatesClientIDAndExpiresOnLookup(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	expiry := uint32(1)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	if !authorizeClient("192.0.2.10", "workstation", 40022, token).Authorized {
		t.Fatal("expected client to be authorized")
	}
	if !isClientAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("192.0.2.10"), "workstation") {
		t.Fatal("expected matching client id to be authorized")
	}
	if isClientAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("192.0.2.10"), "other-client") {
		t.Fatal("different client id must not share authorization")
	}

	muxClient.Lock()
	for key, state := range allClientList[&globalConfig.ForwardConfigs[0]] {
		state.ExpiresAt = time.Now().Add(-time.Second)
		allClientList[&globalConfig.ForwardConfigs[0]][key] = state
	}
	muxClient.Unlock()
	if isClientAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("192.0.2.10"), "workstation") {
		t.Fatal("expired authorization must fail during lookup")
	}
}

func TestGlobalDenyOverridesClientAuthorization(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	expiry := uint32(60)
	globalConfig = &config{
		ServerID:      "connauth-server",
		AuthAddr:      "127.0.0.1:40100",
		GlobalDenyIPs: []accessRule{{IP: "192.0.2.10"}},
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	if !authorizeClient("192.0.2.10", "workstation", 40022, token).Authorized {
		t.Fatal("expected token authorization state to be written")
	}
	if isClientAuthed(&globalConfig.ForwardConfigs[0], net.ParseIP("192.0.2.10"), "workstation") {
		t.Fatal("global deny IP must override token authorization")
	}
}

func TestAuthorizationStateHasGlobalCapacityLimit(t *testing.T) {
	token := "token-abcdefghijklmnopqrstuvwxyz"
	expiry := uint32(60)
	globalConfig = &config{
		ServerID: "connauth-server",
		AuthAddr: "127.0.0.1:40100",
		ForwardConfigs: []forwardConfig{{
			BindPort:        40022,
			ForwardAddr:     "127.0.0.1:22",
			AllowTokens:     []accessRule{{Token: token}},
			AuthExpiredTime: &expiry,
		}},
	}
	initClientList()
	previousLimit := maxAuthorizedClients
	maxAuthorizedClients = 1
	defer func() {
		maxAuthorizedClients = previousLimit
	}()

	if !authorizeClient("192.0.2.10", "workstation", 40022, token).Authorized {
		t.Fatal("expected first authorization to fit capacity")
	}
	if authorizeClient("192.0.2.11", "workstation", 40022, token).Authorized {
		t.Fatal("expected second authorization to be rejected at capacity")
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatalf("close udp: %v", err)
	}
	return addr
}

func startAuthForTest(t *testing.T, addr string) func() {
	t.Helper()
	stop := make(chan struct{})
	done, err := waitForAuth(addr, stop)
	if err != nil {
		t.Fatalf("waitForAuth failed: %v", err)
	}
	return func() {
		close(stop)
		<-done
	}
}

func dialUDPForTest(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	dest, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	return conn
}

func sendChallengeAuthForTest(addr string, keyID string, key string, serverID string, clientID string, token string, port uint16) error {
	conn, err := net.DialUDP("udp", nil, mustResolveUDPAddr(addr))
	if err != nil {
		return err
	}
	defer conn.Close()
	challenge, err := sendChallengeRequest(conn, keyID, key, serverID, clientID, "client-nonce", port)
	if err != nil {
		return err
	}
	return sendChallengeResponse(conn, keyID, key, challenge, token)
}

func mustResolveUDPAddr(addr string) *net.UDPAddr {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	return udpAddr
}

func sendChallengeRequestForTest(t *testing.T, conn *net.UDPConn, key string, clientNonce string, port uint16) authproto.Challenge {
	t.Helper()
	challenge, err := sendChallengeRequest(conn, "primary-2026-06", key, "connauth-server", "workstation", clientNonce, port)
	if err != nil {
		t.Fatalf("send challenge request: %v", err)
	}
	return challenge
}

func sendChallengeRequest(conn *net.UDPConn, keyID string, key string, serverID string, clientID string, clientNonce string, port uint16) (authproto.Challenge, error) {
	req := authproto.ChallengeRequest{
		Type:        authproto.MessageTypeChallengeRequest,
		ServerID:    serverID,
		ClientID:    clientID,
		Port:        port,
		ClientNonce: clientNonce,
		Timestamp:   time.Now().Unix(),
	}
	plain, err := json.Marshal(req)
	if err != nil {
		return authproto.Challenge{}, err
	}
	sealed, err := authproto.Seal([]byte(key), authproto.Context{KeyID: keyID, ServerID: serverID}, plain)
	if err != nil {
		return authproto.Challenge{}, err
	}
	env, err := json.Marshal(authproto.Envelope{KeyID: keyID, ServerID: serverID, Payload: sealed})
	if err != nil {
		return authproto.Challenge{}, err
	}
	if _, err := conn.Write(env); err != nil {
		return authproto.Challenge{}, err
	}
	raw := readUDPWithTimeout(conn, time.Second)
	if len(raw) == 0 {
		return authproto.Challenge{}, fmt.Errorf("no challenge response")
	}
	var respEnv authproto.Envelope
	if err := json.Unmarshal(raw, &respEnv); err != nil {
		return authproto.Challenge{}, err
	}
	opened, err := authproto.Open([]byte(key), authproto.Context{KeyID: respEnv.KeyID, ServerID: respEnv.ServerID}, respEnv.Payload)
	if err != nil {
		return authproto.Challenge{}, err
	}
	var challenge authproto.Challenge
	if err := json.Unmarshal(opened, &challenge); err != nil {
		return authproto.Challenge{}, err
	}
	return challenge, nil
}

func sendChallengeResponseForTest(t *testing.T, conn *net.UDPConn, key string, challenge authproto.Challenge, token string) {
	t.Helper()
	if err := sendChallengeResponse(conn, "primary-2026-06", key, challenge, token); err != nil {
		t.Fatalf("send challenge response: %v", err)
	}
}

func sendChallengeResponse(conn *net.UDPConn, keyID string, key string, challenge authproto.Challenge, token string) error {
	packet, err := buildChallengeResponsePacket(keyID, key, challenge, token)
	if err != nil {
		return err
	}
	_, err = conn.Write(packet)
	return err
}

func buildChallengeResponsePacket(keyID string, key string, challenge authproto.Challenge, token string) ([]byte, error) {
	resp := authproto.ChallengeResponse{
		Type:        authproto.MessageTypeChallengeResponse,
		ServerID:    challenge.ServerID,
		ClientID:    challenge.ClientID,
		Port:        challenge.Port,
		ClientNonce: challenge.ClientNonce,
		ServerNonce: challenge.ServerNonce,
		Token:       token,
		Timestamp:   time.Now().Unix(),
	}
	plain, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	sealed, err := authproto.Seal([]byte(key), authproto.Context{KeyID: keyID, ServerID: challenge.ServerID}, plain)
	if err != nil {
		return nil, err
	}
	env, err := json.Marshal(authproto.Envelope{KeyID: keyID, ServerID: challenge.ServerID, Payload: sealed})
	if err != nil {
		return nil, err
	}
	return env, nil
}

func readUDPWithTimeout(conn *net.UDPConn, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func clearAuthedIPForTest(cfg *forwardConfig, ip string) {
	muxClient.Lock()
	defer muxClient.Unlock()
	for key := range allClientList[cfg] {
		if key.IP == ip {
			delete(allClientList[cfg], key)
		}
	}
}

func waitForClientAuthForTest(cfg *forwardConfig, ip net.IP, clientID string) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if isClientAuthed(cfg, ip, clientID) {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
