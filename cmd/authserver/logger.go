package main

import (
	safelogger "connauth/utils/logger"
	log "github.com/sirupsen/logrus"
	"strings"
)

func initLogger(cfg *config) error {
	if cfg.Logger.AliyunSLS.Enabled {
		slsCfg := safelogger.AliyunSLSConfig{
			Enabled:         cfg.Logger.AliyunSLS.Enabled,
			Endpoint:        cfg.Logger.AliyunSLS.Endpoint,
			ProjectName:     cfg.Logger.AliyunSLS.ProjectName,
			LogStoreName:    cfg.Logger.AliyunSLS.LogStoreName,
			Topic:           cfg.Logger.AliyunSLS.Topic,
			AccessKeyID:     cfg.Logger.AliyunSLS.AccessKeyID,
			AccessKeySecret: cfg.Logger.AliyunSLS.AccessKeySecret,
		}
		hook, err := safelogger.NewSLSHook(slsCfg)
		if err != nil {
			return err
		}
		if hook != nil {
			log.AddHook(hook)
		}
	}
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
