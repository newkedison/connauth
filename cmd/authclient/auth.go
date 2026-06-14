package main

import (
	"connauth/utils"
	"connauth/utils/authproto"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func auth(server *serverConfig, req *utils.AuthRequest) error {
	dest, err := net.ResolveUDPAddr("udp", server.Addr)
	if err != nil {
		return fmt.Errorf("cannot resolve address %s: %v", server.Addr, err)
	}
	conn, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		return fmt.Errorf("dial to %s fail: %v", server.Addr, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	clientNonce, err := authproto.RandomNonceString()
	if err != nil {
		return fmt.Errorf("generate client nonce failed: %v", err)
	}
	challengeReq := authproto.ChallengeRequest{
		Type:        authproto.MessageTypeChallengeRequest,
		ServerID:    server.ServerID,
		ClientID:    globalConfig.ClientID,
		Port:        req.Port,
		ClientNonce: clientNonce,
		Timestamp:   time.Now().Unix(),
	}
	buf, err := sealMessage(server, challengeReq)
	if err != nil {
		return fmt.Errorf("build challenge request failed: %v", err)
	}
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write challenge request failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, authproto.MaxPacketSize)
	n, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("read challenge failed: %v; check server reachability and system time sync", err)
	}
	challenge, err := openChallenge(server, respBuf[:n])
	if err != nil {
		return fmt.Errorf("challenge validation failed: %v; check system time sync", err)
	}
	if challenge.ServerID != server.ServerID ||
		challenge.ClientID != globalConfig.ClientID ||
		challenge.Port != req.Port ||
		challenge.ClientNonce != clientNonce {
		return fmt.Errorf("challenge binding mismatch")
	}
	response := authproto.ChallengeResponse{
		Type:        authproto.MessageTypeChallengeResponse,
		ServerID:    server.ServerID,
		ClientID:    globalConfig.ClientID,
		Port:        req.Port,
		ClientNonce: clientNonce,
		ServerNonce: challenge.ServerNonce,
		Token:       req.Token,
		Timestamp:   time.Now().Unix(),
	}
	buf, err = sealMessage(server, response)
	if err != nil {
		return fmt.Errorf("build challenge response failed: %v", err)
	}
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write challenge response failed: %v", err)
	}
	return nil
}

func sealMessage(server *serverConfig, msg interface{}) ([]byte, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	sealed, err := authproto.Seal([]byte(server.Key), authproto.Context{KeyID: server.KeyID, ServerID: server.ServerID}, body)
	if err != nil {
		return nil, err
	}
	env, err := json.Marshal(authproto.Envelope{KeyID: server.KeyID, ServerID: server.ServerID, Payload: sealed})
	if err != nil {
		return nil, err
	}
	return env, nil
}

func openChallenge(server *serverConfig, packet []byte) (authproto.Challenge, error) {
	var env authproto.Envelope
	if err := json.Unmarshal(packet, &env); err != nil {
		return authproto.Challenge{}, err
	}
	if err := env.Validate(); err != nil {
		return authproto.Challenge{}, err
	}
	if env.KeyID != server.KeyID || env.ServerID != server.ServerID {
		return authproto.Challenge{}, fmt.Errorf("challenge envelope mismatch")
	}
	plain, err := authproto.Open([]byte(server.Key), authproto.Context{KeyID: env.KeyID, ServerID: env.ServerID}, env.Payload)
	if err != nil {
		return authproto.Challenge{}, err
	}
	var challenge authproto.Challenge
	if err := json.Unmarshal(plain, &challenge); err != nil {
		return authproto.Challenge{}, err
	}
	if challenge.Type != authproto.MessageTypeChallenge {
		return authproto.Challenge{}, fmt.Errorf("invalid challenge type")
	}
	if challenge.ExpiresAt <= time.Now().Unix() {
		return authproto.Challenge{}, fmt.Errorf("challenge expired")
	}
	if challenge.ServerNonce == "" {
		return authproto.Challenge{}, fmt.Errorf("server nonce cannot be empty")
	}
	return challenge, nil
}

func startAuthOfServer(server *serverConfig, stop <-chan struct{}) {
	for i := range server.AuthConfigs {
		go func(cfg authConfig) {
			log.Infof("start auth to port %d, re-auth interval %d seconds",
				cfg.Port, *cfg.Interval)
			request := utils.NewAuthRequest(cfg.Token, cfg.Port)
			if !request.IsValid() {
				log.Warnf("request invalid, stop auth for port %d", cfg.Port)
				return
			}
			ticker := time.NewTicker(time.Duration(*cfg.Interval) * time.Second)
			defer ticker.Stop()
			failCount := 0
			nextAlarmCount := 1
		Loop:
			for {
				if err := auth(server, request); err != nil {
					log.Infof("auth failed: %v", err)
					failCount++
					if failCount >= nextAlarmCount {
						log.Warnf("[%4d]auth to port %d failed: %v",
							failCount, cfg.Port, err)
						nextAlarmCount = nextAlarmCount * 10
					}
				} else {
					log.Debugf("auth port %d success", cfg.Port)
					failCount = 0
					nextAlarmCount = 1
				}
				select {
				case <-stop:
					break Loop
				case <-ticker.C:
					continue
				}
			}
			log.Debug("ticker stopped")
		}(server.AuthConfigs[i])
	}
}

func startAllAuth(stop <-chan struct{}) {
	for i := range globalConfig.Servers {
		server := &globalConfig.Servers[i]
		startAuthOfServer(server, stop)
	}
}
