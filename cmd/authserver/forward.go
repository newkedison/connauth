package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"strconv"
	"time"
)

func forward(source io.ReadWriteCloser, dest io.ReadWriteCloser) {
	defer dest.Close()
	defer source.Close()
	_, _ = io.Copy(dest, source)
}

func handleConn(source *net.TCPConn, forwardDestAddr string) error {
	dest, err := net.Dial("tcp", forwardDestAddr)
	if err != nil {
		_ = source.Close()
		return fmt.Errorf("connect to %s failed: %v", forwardDestAddr, err)
	}

	_ = source.SetKeepAlive(true)
	_ = source.SetKeepAlivePeriod(time.Second * 60)

	go forward(source, dest)
	forward(dest, source)
	return nil
}

func startForward(cfg *forwardConfig) error {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(int(cfg.BindPort)))
	if err != nil {
		return fmt.Errorf("listen on port %d failed: %v", cfg.BindPort, err)
	}
	log.Infof("listening on %d, will forward to %s", cfg.BindPort, cfg.ForwardAddr)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Warnf("accept new connection on port %d fail: %v", cfg.BindPort, err)
				continue
			}
			log.Infof("port %d receive new connection from %v",
				cfg.BindPort, conn.RemoteAddr())
			if isIPAuthed(cfg, conn.RemoteAddr().(*net.TCPAddr).IP) {
				log.Infof("%v was authed", conn.RemoteAddr())
				go func() {
					if err := handleConn(conn.(*net.TCPConn), cfg.ForwardAddr); err != nil {
						log.Warnf("handle connection (from %s to %d) failed: %v", conn.RemoteAddr().String(), cfg.BindPort, err)
						_ = conn.Close()
					}
				}()
			} else {
				log.Infof("%v haven't auth yet, close after %d ms",
					conn.RemoteAddr(), *cfg.DropDelayTime)
				if *cfg.DropDelayTime == 0 {
					_ = conn.Close()
				} else {
					time.AfterFunc(time.Duration(*cfg.DropDelayTime)*time.Millisecond, func() {
						log.Infof("%v was closed", conn.RemoteAddr())
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
