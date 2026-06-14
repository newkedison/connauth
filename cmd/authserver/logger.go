package main

import (
	safelogger "connauth/utils/logger"
	"connauth/utils/logrus/hooks"
	log "github.com/sirupsen/logrus"
	"strings"
)

func initLogger(cfg *config) error {
	if cfg.RedisLogger.Enabled {
		c := hooks.HookConfig{
			Key:      cfg.RedisLogger.Key,
			Format:   "v0",
			App:      "app",
			Host:     cfg.RedisLogger.Addr,
			Password: cfg.RedisLogger.Password,
			Hostname: "",
			Port:     cfg.RedisLogger.Port,
			DB:       cfg.RedisLogger.DB,
			MaxSize:  cfg.RedisLogger.MaxSize,
		}
		if hook, err := hooks.NewRedisHook(c); err == nil {
			log.AddHook(hook)
		} else {
			return err
		}
	}
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
