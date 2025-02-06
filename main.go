package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
)

// Default if not set at build time
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)
var identity *Identity
var ocspCertManager *OCSPCertManager
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

	identity = &Identity{PrivateKeyPath: Config.PrivateKeyPath}
	err = identity.Init()
	if err != nil {
		Logger.Error("Failed to init identity", "error", err)
		os.Exit(1)
	}

	ocspCertManager = &OCSPCertManager{certsFolderPath: Config.CertsFolderPath, responders: make(map[string]OCSPResponder)}

	err = ocspCertManager.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err)
		os.Exit(1)
	}

	go StartPrivateListener()
	go StartPublicListener()
}
