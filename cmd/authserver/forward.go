package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type connectionLimiter struct {
	mux       sync.Mutex
	global    int
	byIP      map[string]int
	maxGlobal int
	maxPerIP  int
}

func newConnectionLimiter(maxGlobal uint32, maxPerIP uint32) *connectionLimiter {
	return &connectionLimiter{
		byIP:      make(map[string]int),
		maxGlobal: int(maxGlobal),
		maxPerIP:  int(maxPerIP),
	}
}

func (l *connectionLimiter) acquire(ip net.IP) bool {
	l.mux.Lock()
	defer l.mux.Unlock()
	ipString := ip.String()
	if l.maxGlobal > 0 && l.global >= l.maxGlobal {
		return false
	}
	if l.maxPerIP > 0 && l.byIP[ipString] >= l.maxPerIP {
		return false
	}
	l.global++
	l.byIP[ipString]++
	return true
}

func (l *connectionLimiter) release(ip net.IP) {
	l.mux.Lock()
	defer l.mux.Unlock()
	ipString := ip.String()
	if l.global > 0 {
		l.global--
	}
	if l.byIP[ipString] > 1 {
		l.byIP[ipString]--
	} else {
		delete(l.byIP, ipString)
	}
}

func forward(source io.ReadWriteCloser, dest io.ReadWriteCloser) {
	defer dest.Close()
	defer source.Close()
	_, _ = io.Copy(dest, source)
}

func handleConn(source *net.TCPConn, forwardDestAddr string, dialTimeout time.Duration, idleTimeout time.Duration) error {
	dest, err := net.DialTimeout("tcp", forwardDestAddr, dialTimeout)
	if err != nil {
		_ = source.Close()
		return fmt.Errorf("connect to %s failed: %v", forwardDestAddr, err)
	}

	_ = source.SetKeepAlive(true)
	_ = source.SetKeepAlivePeriod(time.Second * 60)
	if idleTimeout > 0 {
		deadline := time.Now().Add(idleTimeout)
		_ = source.SetDeadline(deadline)
		if tcpDest, ok := dest.(*net.TCPConn); ok {
			_ = tcpDest.SetDeadline(deadline)
		}
	}

	go forward(source, dest)
	forward(dest, source)
	return nil
}

func startForward(cfg *forwardConfig) error {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(int(cfg.BindPort)))
	if err != nil {
		return fmt.Errorf("listen on port %d failed: %v", cfg.BindPort, err)
	}
	log.WithFields(log.Fields{
		"event":        "forward_listening",
		"port":         cfg.BindPort,
		"forward_addr": cfg.ForwardAddr,
		"result":       "success",
	}).Infof("listening on %d, will forward to %s", cfg.BindPort, cfg.ForwardAddr)
	limiter := newConnectionLimiter(*cfg.MaxConnGlobal, *cfg.MaxConnPerIP)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.WithFields(log.Fields{
					"event":  "forward_accept_failed",
					"port":   cfg.BindPort,
					"result": "failed",
					"error":  err.Error(),
				}).Warnf("accept new connection on port %d fail: %v", cfg.BindPort, err)
				continue
			}
			remoteAddr := conn.RemoteAddr().String()
			remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP
			if isIPAuthed(cfg, remoteIP) {
				log.WithFields(log.Fields{
					"event":       "forward_authorized",
					"source_ip":   remoteIP.String(),
					"source_addr": remoteAddr,
					"port":        cfg.BindPort,
					"result":      "authorized",
				}).Infof("port %d receive authorized connection from %v", cfg.BindPort, conn.RemoteAddr())
				go func() {
					if !limiter.acquire(remoteIP) {
						log.WithFields(log.Fields{
							"event":       "forward_rejected",
							"source_ip":   remoteIP.String(),
							"source_addr": remoteAddr,
							"port":        cfg.BindPort,
							"result":      "rejected",
							"reason":      "resource_limit",
						}).Warnf("connection from %s rejected by resource limit", conn.RemoteAddr().String())
						_ = conn.Close()
						return
					}
					defer limiter.release(remoteIP)
					if err := handleConn(conn.(*net.TCPConn), cfg.ForwardAddr, time.Duration(*cfg.DialTimeoutMS)*time.Millisecond, time.Duration(*cfg.IdleTimeoutMS)*time.Millisecond); err != nil {
						log.WithFields(log.Fields{
							"event":        "forward_failed",
							"source_ip":    remoteIP.String(),
							"source_addr":  remoteAddr,
							"port":         cfg.BindPort,
							"forward_addr": cfg.ForwardAddr,
							"result":       "failed",
							"error":        err.Error(),
						}).Warnf("handle connection (from %s to %d) failed: %v", conn.RemoteAddr().String(), cfg.BindPort, err)
						_ = conn.Close()
					}
				}()
			} else {
				log.WithFields(log.Fields{
					"event":         "forward_unauthorized",
					"source_ip":     remoteIP.String(),
					"source_addr":   remoteAddr,
					"port":          cfg.BindPort,
					"result":        "rejected",
					"reason":        "not_authed",
					"drop_delay_ms": *cfg.DropDelayTime,
				}).Warnf("%v haven't auth yet, close after %d ms", conn.RemoteAddr(), *cfg.DropDelayTime)
				if *cfg.DropDelayTime == 0 {
					_ = conn.Close()
				} else {
					time.AfterFunc(time.Duration(*cfg.DropDelayTime)*time.Millisecond, func() {
						log.WithFields(log.Fields{
							"event":       "forward_closed",
							"source_ip":   remoteIP.String(),
							"source_addr": remoteAddr,
							"port":        cfg.BindPort,
							"result":      "closed",
							"reason":      "drop_delay_elapsed",
						}).Debugf("%v was closed", conn.RemoteAddr())
						_ = conn.Close()
					})
				}
			}
		}
	}()
	go func() {
		for {
			refreshClientList(cfg)
			time.Sleep(time.Second)
		}
	}()
	return nil
}
