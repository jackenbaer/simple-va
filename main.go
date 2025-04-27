package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"simple-va/security"
	"simple-va/storage"
)

// Default, will be overwritten at build time by the pipeline
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)
var identity *Identity
var ocspCertManager *OCSPCertManager
var CertStatus *storage.CertStatus
var Logger *slog.Logger
var Config Configuration

func StartPublicListener() {
	http.HandleFunc("/ocsp", HandleOcsp)
	log.Fatal(http.ListenAndServe(Config.HostnamePrivateApi, nil))
}

func StartPrivateListener(apiKeyStore *security.APIKeyStore) {
	prvHttpHandler := &PrivateHTTPHandler{apiKeyStore: apiKeyStore}

	http.HandleFunc("/createnewcsr", prvHttpHandler.HandleCreateNewCsr)
	http.HandleFunc("/uploadsignedcert", prvHttpHandler.HandleUploadSignedCert)
	http.HandleFunc("/removeresponder", prvHttpHandler.HandleRemoveResponder)
	http.HandleFunc("/listcerts", prvHttpHandler.HandleListCerts)

	err := http.ListenAndServe(Config.HostnamePublicApi, nil)
	if err != nil {
		Logger.Error("Error starting private API listener", "stack", string(debug.Stack()))
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
		Logger.Error("Failed to validate configuration", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	identity = &Identity{PrivateKeyPath: Config.PrivateKeyPath}
	err = identity.Init()
	if err != nil {
		Logger.Error("Failed to init identity", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	APIKeyStore, err := security.NewAPIKeyStoreFromFile(Config.HashedApiKeysPath)
	if err != nil {
		Logger.Error("Could not load api keys", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}
	if !APIKeyStore.AllAPIKeysValid() {
		Logger.Error("Invalid API key or format detected", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	ocspCertManager = &OCSPCertManager{certsFolderPath: Config.CertsFolderPath, responders: make(map[string]OCSPResponder)}

	err = ocspCertManager.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	CertStatus = &storage.CertStatus{CertStatusPath: Config.CertStatusPath}
	err = CertStatus.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}
	go StartPrivateListener(APIKeyStore)
	StartPublicListener()
}
