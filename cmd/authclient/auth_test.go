package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"connauth/utils"
	"connauth/utils/authproto"
	log "github.com/sirupsen/logrus"
)

func TestAuthPerformsChallengeResponseHandshake(t *testing.T) {
	key := "abcdefghijklmnopqrstuvwxyz123456"
	token := "token-abcdefghijklmnopqrstuvwxyz"
	serverID := "connauth-server"
	clientID := "workstation"
	port := uint16(40022)
	ready := make(chan string, 1)
	done := make(chan authproto.ChallengeResponse, 1)
	errs := make(chan error, 1)
	go runChallengeServerForClientTest(t, ready, done, errs, key, "primary-2026-06", serverID, clientID, port)
	addr := <-ready
	globalConfig = &config{ClientID: clientID}

	err := auth(&serverConfig{
		Addr:     addr,
		ServerID: serverID,
		KeyID:    "primary-2026-06",
		Key:      key,
	}, utils.NewAuthRequest(token, port))
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	select {
	case err := <-errs:
		t.Fatalf("stub server failed: %v", err)
	case resp := <-done:
		if resp.Token != token {
			t.Fatal("challenge response token mismatch")
		}
		if resp.ServerID != serverID || resp.ClientID != clientID || resp.Port != port {
			t.Fatalf("challenge response binding mismatch: %+v", resp)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for challenge response")
	}
}

func TestAuthRejectsChallengeWithWrongClientNonce(t *testing.T) {
	key := "abcdefghijklmnopqrstuvwxyz123456"
	token := "token-abcdefghijklmnopqrstuvwxyz"
	serverID := "connauth-server"
	clientID := "workstation"
	port := uint16(40022)
	ready := make(chan string, 1)
	done := make(chan authproto.ChallengeResponse, 1)
	errs := make(chan error, 1)
	go runChallengeServerWithNonceOverrideForClientTest(t, ready, done, errs, key, "primary-2026-06", serverID, clientID, port, "wrong-client-nonce")
	addr := <-ready
	globalConfig = &config{ClientID: clientID}

	err := auth(&serverConfig{
		Addr:     addr,
		ServerID: serverID,
		KeyID:    "primary-2026-06",
		Key:      key,
	}, utils.NewAuthRequest(token, port))
	if err == nil {
		t.Fatal("expected auth to reject challenge with wrong client nonce")
	}
	select {
	case resp := <-done:
		t.Fatalf("client must not send challenge response after bad challenge: %+v", resp)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStartAuthOfServerDoesNotLogToken(t *testing.T) {
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
	interval := uint32(60)
	stop := make(chan struct{})
	done := startAuthOfServer(&serverConfig{
		Addr:     "127.0.0.1:1",
		ServerID: "connauth-server",
		KeyID:    "primary-2026-06",
		Key:      "test-key",
		AuthConfigs: []authConfig{
			{Token: token, Port: 2222, Interval: &interval},
		},
	}, stop)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	<-done

	if strings.Contains(buf.String(), token) {
		t.Fatalf("log output contains token: %s", buf.String())
	}
}

func runChallengeServerForClientTest(t *testing.T, ready chan<- string, done chan<- authproto.ChallengeResponse, errs chan<- error, key string, keyID string, serverID string, clientID string, port uint16) {
	t.Helper()
	runChallengeServerWithNonceOverrideForClientTest(t, ready, done, errs, key, keyID, serverID, clientID, port, "")
}

func runChallengeServerWithNonceOverrideForClientTest(t *testing.T, ready chan<- string, done chan<- authproto.ChallengeResponse, errs chan<- error, key string, keyID string, serverID string, clientID string, port uint16, clientNonceOverride string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		errs <- err
		return
	}
	defer conn.Close()
	ready <- conn.LocalAddr().String()

	buf := make([]byte, authproto.MaxPacketSize)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, peer, err := conn.ReadFromUDP(buf)
	if err != nil {
		errs <- err
		return
	}
	var reqEnv authproto.Envelope
	if err := json.Unmarshal(buf[:n], &reqEnv); err != nil {
		errs <- err
		return
	}
	if reqEnv.KeyID != keyID || reqEnv.ServerID != serverID {
		errs <- fmt.Errorf("request envelope mismatch: %+v", reqEnv)
		return
	}
	plain, err := authproto.Open([]byte(key), authproto.Context{KeyID: keyID, ServerID: serverID}, reqEnv.Payload)
	if err != nil {
		errs <- err
		return
	}
	var req authproto.ChallengeRequest
	if err := json.Unmarshal(plain, &req); err != nil {
		errs <- err
		return
	}
	if req.Type != authproto.MessageTypeChallengeRequest || req.ServerID != serverID || req.ClientID != clientID || req.Port != port {
		errs <- fmt.Errorf("challenge request mismatch: %+v", req)
		return
	}
	clientNonce := req.ClientNonce
	if clientNonceOverride != "" {
		clientNonce = clientNonceOverride
	}
	challenge := authproto.Challenge{
		Type:        authproto.MessageTypeChallenge,
		ServerID:    serverID,
		ClientID:    clientID,
		Port:        port,
		ClientNonce: clientNonce,
		ServerNonce: "server-nonce",
		ExpiresAt:   time.Now().Add(authproto.ChallengeTTL).Unix(),
	}
	challengeBody, err := json.Marshal(challenge)
	if err != nil {
		errs <- err
		return
	}
	sealed, err := authproto.Seal([]byte(key), authproto.Context{KeyID: keyID, ServerID: serverID}, challengeBody)
	if err != nil {
		errs <- err
		return
	}
	respEnv, err := json.Marshal(authproto.Envelope{KeyID: keyID, ServerID: serverID, Payload: sealed})
	if err != nil {
		errs <- err
		return
	}
	if _, err := conn.WriteToUDP(respEnv, peer); err != nil {
		errs <- err
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = conn.ReadFromUDP(buf)
	if err != nil {
		errs <- err
		return
	}
	var finalEnv authproto.Envelope
	if err := json.Unmarshal(buf[:n], &finalEnv); err != nil {
		errs <- err
		return
	}
	finalPlain, err := authproto.Open([]byte(key), authproto.Context{KeyID: keyID, ServerID: serverID}, finalEnv.Payload)
	if err != nil {
		errs <- err
		return
	}
	var final authproto.ChallengeResponse
	if err := json.Unmarshal(finalPlain, &final); err != nil {
		errs <- err
		return
	}
	done <- final
}
