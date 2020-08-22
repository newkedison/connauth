package main

import (
	log "github.com/sirupsen/logrus"
	"strings"
)

func initLogger(cfg *config) error {
	switch strings.ToLower(cfg.LogLevel) {
	case "p", "panic":
		log.SetLevel(log.PanicLevel)
	case "f", "fatal":
		log.SetLevel(log.FatalLevel)
	case "e", "error":
		log.SetLevel(log.ErrorLevel)
	case "w", "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "i", "info":
		log.SetLevel(log.InfoLevel)
	case "d", "debug":
		log.SetLevel(log.DebugLevel)
	case "t", "trace", "v", "verbose":
		log.SetLevel(log.TraceLevel)
	default:
		log.SetLevel(log.WarnLevel)
	}
	formatter := &log.TextFormatter{}
	formatter.FullTimestamp = true
	formatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(formatter)
	return nil
}
