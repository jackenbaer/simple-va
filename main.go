package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
)

var (
	Version   = "dev"  // Default if not set at build time
	Commit    = "none" // Default if not set
	BuildTime = "unknown"
)
var responderMap map[string]OCSPResponder
var identity *Identity
var Logger *slog.Logger
var Config *Configuration

func ensurePathExists(path string) error {
	_, err := os.Stat(path)

	if os.IsNotExist(err) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create path: %w", err)
		}
		fmt.Println("Path created:", path)
	} else if err != nil {
		return fmt.Errorf("error checking path: %w", err)
	}
	return nil
}

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

func init() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo, AddSource: true})
	Logger = slog.New(handler)
	Logger.Info("#########################  STARTING  #########################", "version", Version, "commit", Commit, "build_time", BuildTime)

	Config.LoadFromFile("./config.ini")
	responderMap = make(map[string]OCSPResponder)
	identity = &Identity{PrivateKeyPath: Config.PrivateKeyPath, CertsFolderPath: Config.CertsFolderPath}
	err := identity.Init()
	if err != nil {
		Logger.Error("Failed to init identity", "error", err)
		os.Exit(1)
	}

}

func main() {

	go StartPrivateListener()
	go StartPublicListener()
}
