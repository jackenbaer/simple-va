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
	Version    = "dev"
	Commit     = "none"
	BuildTime  = "unknown"
	ApiVersion = "v1"
)
var identity *Identity
var ocspCertManager *OCSPCertManager
var CertStatus *storage.CertStatus
var Logger *slog.Logger
var Config *Configuration
var ApiKeys *security.ApiKeyStore

func StartPublicListener() {
	http.HandleFunc("/ocsp", HandleOcsp)
	log.Fatal(http.ListenAndServe(Config.HostnamePrivateApi, nil))
}

func StartPrivateListener() {
	http.HandleFunc(fmt.Sprintf("/%s/createnewcsr", ApiVersion), HandleCreateNewCsr)
	http.HandleFunc(fmt.Sprintf("/%s/uploadsignedcert", ApiVersion), HandleUploadSignedCert)
	http.HandleFunc(fmt.Sprintf("/%s/removeresponder", ApiVersion), HandleRemoveResponder)
	http.HandleFunc(fmt.Sprintf("/%s/listcerts", ApiVersion), HandleListResponderCerts)
	http.HandleFunc(fmt.Sprintf("/%s/addrevokedcert", ApiVersion), HandleAddRevokedCert)
	http.HandleFunc(fmt.Sprintf("/%s/listrevokedcerts", ApiVersion), HandleListRevokedCerts)

	err := http.ListenAndServe(Config.HostnamePublicApi, nil)
	if err != nil {
		Logger.Error("Error starting private API listener", "stack", string(debug.Stack()))
		os.Exit(1)
	}

}

func main() {
	var versionFlag bool

	flag.BoolVar(&versionFlag, "version", false, "Print the version of the binary")
	flag.BoolVar(&versionFlag, "v", false, "Print the version of the binary (shorthand)")

	flag.Parse()

	if versionFlag {
		fmt.Printf("%s,%s,%s,%s\n", Version, Commit, BuildTime, ApiVersion)
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

	ApiKeys = &security.ApiKeyStore{HashedApiKeyFile: Config.HashedApiKeysPath}
	err = ApiKeys.Init()
	if err != nil {
		Logger.Error("Loading Api Key list failed", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}
	if !ApiKeys.Validate() {
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

	go ListenForSignals()
	go StartPrivateListener()
	StartPublicListener()
}
