package main

import (
	"os"
	"os/signal"
	"syscall"
)

func onTerm() {
	CertStatus.Mu.Lock()
	defer CertStatus.Mu.Unlock()
	os.Exit(0)
}

func ListenForSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigs
		switch sig {
		case syscall.SIGTERM:
			Logger.Info("Received SIGTERM")
			go onTerm()
		default:
			Logger.Error("Received unhandled signal",
				"signal", sig,
			)
		}
	}
}
