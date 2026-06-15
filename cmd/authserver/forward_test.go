package main

import (
	"net"
	"strconv"
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

func TestStartForwardStopsAndReleasesListener(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backend.Close()
	bindPort := freeTCPPort(t)
	cfg := forwardConfig{
		BindPort:    bindPort,
		ForwardAddr: backend.Addr().String(),
	}
	cfg.SetDefaultValue()
	globalConfig = &config{}
	initClientList()

	done, err := startForwardWithStop(&cfg, make(chan struct{}))
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	close(done.Stop)
	select {
	case <-done.Done:
	case <-time.After(time.Second):
		t.Fatal("forward listener did not stop")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", intPort(bindPort)))
	if err != nil {
		t.Fatalf("expected bind port to be released: %v", err)
	}
	_ = listener.Close()
}

func TestStartForwardRejectsUnauthorizedConnection(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backend.Close()
	bindPort := freeTCPPort(t)
	cfg := forwardConfig{
		BindPort:    bindPort,
		ForwardAddr: backend.Addr().String(),
	}
	cfg.SetDefaultValue()
	globalConfig = &config{}
	initClientList()

	runtime, err := startForwardWithStop(&cfg, make(chan struct{}))
	if err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer func() {
		close(runtime.Stop)
		<-runtime.Done
	}()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", intPort(bindPort)), time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected unauthorized connection to close")
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func intPort(port uint16) string {
	return strconv.Itoa(int(port))
}
