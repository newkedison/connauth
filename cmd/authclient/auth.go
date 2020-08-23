package main

import (
	"connauth/utils"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func encrypt(req *utils.AuthRequest, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
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
	req.Timestamp = time.Now().Unix()
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("get nonce fail: %v", err)
	}
	req.Nonce = string(nonce)
	buf, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %v", err)
	}
	return gcm.Seal(nonce, nonce, buf, []byte(utils.AdditionalData)), nil
}

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

	buf, err := encrypt(req, []byte(server.Key))
	if err != nil {
		return fmt.Errorf("encrypt failed: %v", err)
	}

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write to ser failed: %v", err)
	}
	return nil
}

func startAuthOfServer(server *serverConfig, stop <-chan struct{}) {
	for i := range server.AuthConfigs {
		go func(cfg authConfig) {
			log.Infof("start auth to port %d with token %s, re-auth interval %d seconds",
				cfg.Port, cfg.Token, *cfg.Interval)
			request := utils.NewAuthRequest(cfg.Token, cfg.Port)
			if !request.IsValid() {
				log.Warnf("request invalid, stop auth for port %d with token %s",
					cfg.Port, cfg.Token)
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
						log.Warnf("[%4d]auth to port %d with token %s failed: %v",
							failCount, cfg.Port, cfg.Token, err)
						nextAlarmCount = nextAlarmCount * 10
					}
				} else {
					log.Debugf("auth port %d with token %s success", cfg.Port, cfg.Token)
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
