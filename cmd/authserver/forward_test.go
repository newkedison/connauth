package main

import (
	"net"
	"testing"
	"time"
)

func TestForwardConfigSetsResourceLimitDefaults(t *testing.T) {
	cfg := forwardConfig{
		BindPort:    40022,
		ForwardAddr: "127.0.0.1:22",
	}
	cfg.SetDefaultValue()
	if *cfg.DropDelayTime != 0 {
		t.Fatalf("expected unauth drop delay default 0, got %d", *cfg.DropDelayTime)
	}
	if *cfg.MaxConnPerIP != 16 {
		t.Fatalf("expected per-IP connection limit default 16, got %d", *cfg.MaxConnPerIP)
	}
	if *cfg.MaxConnGlobal != 1024 {
		t.Fatalf("expected global connection limit default 1024, got %d", *cfg.MaxConnGlobal)
	}
	if *cfg.DialTimeoutMS != 3000 {
		t.Fatalf("expected dial timeout default 3000ms, got %d", *cfg.DialTimeoutMS)
	}
	if *cfg.IdleTimeoutMS != 300000 {
		t.Fatalf("expected idle timeout default 300000ms, got %d", *cfg.IdleTimeoutMS)
	}
}

func TestForwardConfigRejectsUnsafeDropDelay(t *testing.T) {
	delay := uint32(60000)
	cfg := forwardConfig{
		BindPort:      40022,
		ForwardAddr:   "127.0.0.1:22",
		DropDelayTime: &delay,
	}
	if err := cfg.CheckValid(); err == nil {
		t.Fatal("expected long unauth drop delay to be rejected")
	}
}

func TestConnectionLimiterEnforcesGlobalAndPerIPLimits(t *testing.T) {
	limiter := newConnectionLimiter(2, 1)
	ip := net.ParseIP("192.0.2.10")
	if !limiter.acquire(ip) {
		t.Fatal("expected first connection to be accepted")
	}
	if limiter.acquire(ip) {
		t.Fatal("expected second connection from same IP to be rejected")
	}
	otherIP := net.ParseIP("192.0.2.11")
	if !limiter.acquire(otherIP) {
		t.Fatal("expected second global connection from different IP to be accepted")
	}
	if limiter.acquire(net.ParseIP("192.0.2.12")) {
		t.Fatal("expected third global connection to be rejected")
	}
	limiter.release(ip)
	if !limiter.acquire(ip) {
		t.Fatal("expected released IP slot to be reusable")
	}
}

func TestHandleConnUsesDialTimeout(t *testing.T) {
	source, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen source: %v", err)
	}
	defer source.Close()
	dialDone := make(chan error, 1)
	go func() {
		conn, err := net.Dial("tcp", source.Addr().String())
		if err != nil {
			dialDone <- err
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
		dialDone <- nil
	}()
	accepted, err := source.AcceptTCP()
	if err != nil {
		t.Fatalf("accept source: %v", err)
	}
	err = handleConn(accepted, "127.0.0.1:1", 10*time.Millisecond, time.Second)
	if err == nil {
		t.Fatal("expected backend dial to fail")
	}
	if err := <-dialDone; err != nil {
		t.Fatalf("source dial failed: %v", err)
	}
}
