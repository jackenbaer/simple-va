package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
)

var (
	Version = "dev" // Default if not set at build time
)
var responderMap map[string]OCSPResponder
var identity *Identity
var Logger *slog.Logger
var Config *Configuration
var OCSPDb *OCSPDatabase

func StartPublicListener() {
	http.HandleFunc("/ocsp", HandleOcsp)
	log.Fatal(http.ListenAndServe(Config.HostnamePrivateApi, nil))
}

func StartPrivateListener() {
	http.HandleFunc("/createnewcsr", HandleCreateNewCsr)
	http.HandleFunc("/uploadsignedcert", HandleUploadSignedCert)
	http.HandleFunc("/listcerts", HandleListCerts)

	err := http.ListenAndServe(Config.HostnamePublicApi, nil)
	if err != nil {
		Logger.Error("Error starting private API listener")
		os.Exit(1)
	}

}

func main() {
	versionFlag := flag.Bool("version", false, "Print the version of the binary")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s", Version)
		os.Exit(0)
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger = slog.New(handler)
	Logger.Info("#########################  STARTING  #########################", "version", Version, "commit", Commit, "build_time", BuildTime)

	Config.LoadFromFile("./config.ini")
	err := Config.Validate()
	if err != nil {
		Logger.Error("Failed to validate configuration", "error", err)
		os.Exit(1)
	}

	responderMap = make(map[string]OCSPResponder)
	identity = &Identity{PrivateKeyPath: Config.PrivateKeyPath, CertsFolderPath: Config.CertsFolderPath}
	err = identity.Init()
	if err != nil {
		Logger.Error("Failed to init identity", "error", err)
		os.Exit(1)
	}

	go StartPrivateListener()
	go StartPublicListener()
}
