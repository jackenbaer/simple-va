package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

var (
	Version   = "dev"  // Default if not set at build time
	Commit    = "none" // Default if not set
	BuildTime = "unknown"
)
var responderMap map[string]OCSPResponder

var identity *Identity
var Logger *slog.Logger

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

func StartPublicListener(parsedPublicURL *url.URL) {
	http.HandleFunc("/ocsp", HandleOcsp)
	log.Fatal(http.ListenAndServe(parsedPublicURL.String(), nil))
}

func StartPrivateListener(hostnamePrivateApi *url.URL) {
	http.HandleFunc("/createnewcsr", HandleCreateNewCsr)
	http.HandleFunc("/uploadsignedcert", HandleUploadSignedCert)
	http.HandleFunc("/listcerts", HandleListCerts)

	err := http.ListenAndServe(hostnamePrivateApi.String(), nil)
	if err != nil {
		Logger.Error("Error starting private API listener")
		os.Exit(1)
	}

}

func init() {
	responderMap = make(map[string]OCSPResponder)
}

func main() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger := slog.New(handler)

	Logger.Info("Application started",
		"version", Version,
		"commit", Commit,
		"build_time", BuildTime,
	)

	//Config
	hostnamePrivateApi := "localhost:8080"
	hostnamePublicApi := "localhost:8081"
	identityFolder := "."

	//Check Config
	parsedPrivateURL, err := url.Parse(hostnamePrivateApi)
	if err != nil {
		Logger.Error("Failed to parse URL", "error", err)
		os.Exit(1)
	}
	parsedPublicURL, err := url.Parse(hostnamePublicApi)
	if err != nil {
		Logger.Error("Failed to parse URL", "error", err)
		os.Exit(1)
	}
	identityFolderPath, err := filepath.Abs(identityFolder)
	if err != nil {
		Logger.Error("Error getting absolute path", "error", err)
		os.Exit(1)
	}
	//

	err = ensurePathExists(identityFolderPath)
	if err != nil {
		Logger.Error("Error ensuring that path exist", "error", err)
		os.Exit(1)
	}

	identity = &Identity{FolderPath: identityFolderPath}
	err = identity.Init()
	if err != nil {
		Logger.Error("Failed to init identity", "error", err)
		os.Exit(1)
	}

	go StartPrivateListener(parsedPrivateURL)
	go StartPublicListener(parsedPublicURL)
}
