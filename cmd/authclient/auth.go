package main

import (
	"connauth/utils"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

func auth(serverAddr string, req utils.AuthRequest) error {
	dest, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return fmt.Errorf("cannot resolve address %s: %v", serverAddr, err)
	}
	conn, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		return fmt.Errorf("dial to %s fail: %v", serverAddr, err)
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request failed: %v", err)
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
			ticker := time.NewTicker(time.Duration(*cfg.Interval) * time.Second)
			request := utils.AuthRequest{
				Token: cfg.Token,
				Port:  cfg.Port,
			}
			defer ticker.Stop()
			failCount := 0
			nextAlarmCount := 1
		Loop:
			for {
				if err := auth(server.Addr, request); err != nil {
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
