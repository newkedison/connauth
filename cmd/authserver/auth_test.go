package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"connauth/utils"
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
		AuthAddr: authAddr,
		AuthKey:  authKey,
		ForwardConfigs: []forwardConfig{
			{
				BindPort:        2222,
				ForwardAddr:     "127.0.0.1:22",
				AllowTokens:     []string{token},
				AuthExpiredTime: &expiry,
			},
		},
	}
	initClientList()
	if err := waitForAuth(authAddr); err != nil {
		t.Fatalf("waitForAuth failed: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := sendAuthRequest(authAddr, authKey, utils.NewAuthRequest(token, 2222)); err != nil {
		t.Fatalf("send auth request failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if strings.Contains(buf.String(), token) {
		t.Fatalf("log output contains token: %s", buf.String())
	}
}

func TestDeleteOldNonceDoesNotLogAsError(t *testing.T) {
	var buf bytes.Buffer
	previousOut := log.StandardLogger().Out
	previousLevel := log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.ErrorLevel)
	defer func() {
		log.SetOutput(previousOut)
		log.SetLevel(previousLevel)
	}()

	allNonce.Store("old", time.Now().Add(-2*time.Minute).Unix())
	deleteOldNonce()

	if strings.Contains(buf.String(), "nonce count delete") {
		t.Fatalf("nonce cleanup logged at error level: %s", buf.String())
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

func sendAuthRequest(addr string, key string, req *utils.AuthRequest) error {
	dest, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	buf, err := encryptAuthRequestForTest(req, []byte(key))
	if err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}

func encryptAuthRequestForTest(req *utils.AuthRequest, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	cipherKey := sha256.Sum256(key)
	c, err := aes.NewCipher(cipherKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	req.Timestamp = time.Now().Unix()
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req.Nonce = string(nonce)
	plain, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte(utils.AdditionalData)), nil
}
