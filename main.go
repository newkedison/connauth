package main

import (
	"os"
	"path"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	_log "log"

	"connauth/utils/service"
	"github.com/davecgh/go-spew/spew"
)

//noinspection GoUnusedGlobalVariable
var dump = spew.Dump

func getCurrentPath() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return dir
}

// Do all your work in this function
func Main(exit <-chan struct{}) {
	// log some info if you want
	if service.Interactive() {
		log.Debug("Running in terminal.")
	} else {
		log.Debug("Running under service manager.")
	}
	log.Debug("Platform:", service.Platform())
	log.Info("Log level:", log.GetLevel())

	go func() {
		//     dump(globalConfig)
	}()

	// waiting for the exit signal
	<-exit
}

func main() {
	var err error
	if globalConfig, err = readConfig(
		path.Join(getCurrentPath(), DefaultConfigFile)); err != nil {
		_log.Fatalln("Read config fail:", err)
	}
	if err := initLogger(globalConfig); err != nil {
		_log.Fatalln("Config logger fail:", err)
	}

	_ = service.Init(service.Option{
		Name:        globalConfig.Service.ServiceName,
		DisplayName: globalConfig.Service.DisplayName,
		Description: globalConfig.Service.Description,
	})
	err = service.Run(Main)
	if err != nil {
		log.Error(err)
	}
}
