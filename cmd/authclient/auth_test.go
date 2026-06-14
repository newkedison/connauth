package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

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
	startAuthOfServer(&serverConfig{
		Addr: "127.0.0.1:1",
		Key:  "test-key",
		AuthConfigs: []authConfig{
			{Token: token, Port: 2222, Interval: &interval},
		},
	}, stop)
	time.Sleep(50 * time.Millisecond)
	close(stop)

	if strings.Contains(buf.String(), token) {
		t.Fatalf("log output contains token: %s", buf.String())
	}
}
