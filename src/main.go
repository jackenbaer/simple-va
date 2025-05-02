package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
)

// Default, will be overwritten at build time by the pipeline
var (
	Version    = "dev"
	Commit     = "none"
	BuildTime  = "unknown"
	ApiVersion = "v1.0.0"
)
var identity *Identity
var ocspCertManager *OCSPCertManager
var CertStatus *CertState
var Logger *slog.Logger
var Config *Configuration
var ApiKeys *ApiKeyStore

func StartPublicListener() {
	http.HandleFunc("/ocsp", HandleOcsp)
	log.Fatal(http.ListenAndServe(Config.HostnamePrivateApi, nil))
}

func StartPrivateListener() {
	route := func(path, method string, h http.HandlerFunc) {
		http.HandleFunc(fmt.Sprintf("/%s/%s", ApiVersion, path),
			Middleware(method, h))
	}

	route("createnewcsr", http.MethodPost, HandleCreateNewCsr)
	route("uploadsignedcert", http.MethodPost, HandleUploadSignedCert)
	route("removeresponder", http.MethodDelete, HandleRemoveResponder)
	route("listcerts", http.MethodGet, HandleListResponderCerts)
	route("addrevokedcert", http.MethodPost, HandleAddRevokedCert)
	route("removerevokedcert", http.MethodDelete, HandleRemoveRevokedCert)
	route("listrevokedcerts", http.MethodGet, HandleListRevokedCerts)

	if Config.PrivateEndpointCertPath == "" || Config.PrivateEndpointKeyPath == "" {
		err := http.ListenAndServe(Config.HostnamePublicApi, nil)
		if err != nil {
			Logger.Error("Error starting private API listener", "stack", string(debug.Stack()))
			os.Exit(1)
		}
	} else if Config.PrivateEndpointCertPath != "" || Config.PrivateEndpointKeyPath != "" {
		err := http.ListenAndServeTLS(Config.HostnamePublicApi, Config.PrivateEndpointCertPath, Config.PrivateEndpointKeyPath, nil)
		if err != nil {
			Logger.Error("Error starting private TLS API listener", "stack", string(debug.Stack()))
			os.Exit(1)
		}
	} else {
		Logger.Error("Error starting private API listener. Strange tls config")
		os.Exit(1)
	}

}

func main() {
	var versionFlag bool
	var helpFlag bool
	var configPath string

	flag.BoolVar(&helpFlag, "help", false, "Print the help documentation")
	flag.BoolVar(&helpFlag, "h", false, "Print the help documentation")

	flag.BoolVar(&versionFlag, "version", false, "Print the version of the binary")
	flag.BoolVar(&versionFlag, "v", false, "Print the version of the binary")

	flag.StringVar(&configPath, "config", "/etc/simple-va/config.ini", "Path to configuration file")
	flag.StringVar(&configPath, "c", "/etc/simple-va/config.ini", "Path to configuration file ")

	flag.Parse()

	switch {
	case versionFlag:
		fmt.Printf("%s,%s,%s,%s\n", Version, Commit, BuildTime, ApiVersion)
		return
	case helpFlag:
		flag.Usage()
		return
	default:
		fmt.Printf("Using config file: %s\n", configPath)
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger = slog.New(handler)
	Logger.Info("#########################  STARTING  #########################", "version", Version, "commit", Commit, "build_time", BuildTime)

	Config = &Configuration{}
	err := Config.LoadFromFile(configPath)
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

	ApiKeys = &ApiKeyStore{}
	if Config.HashedApiKeysPath != "" {
		err = ApiKeys.LoadFromFile(Config.HashedApiKeysPath)
		if err != nil {
			Logger.Error("Loading Api Key list failed", "error", err, "stack", string(debug.Stack()))
			os.Exit(1)
		}
	}

	ocspCertManager = &OCSPCertManager{certsFolderPath: Config.CertsFolderPath, responders: make(map[string]OCSPResponder)}
	err = ocspCertManager.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	CertStatus = &CertState{CertStatusPath: Config.CertStatusPath}
	err = CertStatus.Init()
	if err != nil {
		Logger.Error("Failed to init ocsp certificate manager", "error", err, "stack", string(debug.Stack()))
		os.Exit(1)
	}

	go ListenForSignals()
	go StartPrivateListener()
	StartPublicListener()
}
