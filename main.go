package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

var (
	Version   = "dev"  // Default if not set at build time
	Commit    = "none" // Default if not set
	BuildTime = "unknown"
)

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

func main() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger := slog.New(handler)

	Logger.Info("Application started",
		"version", Version,
		"commit", Commit,
		"build_time", BuildTime,
	)

	//Config
	hostnamePrivateApi := ":8080"
	identityFolder := "."
	//hostnamePublicApi

	identityFolderPath, err := filepath.Abs(identityFolder)
	if err != nil {
		Logger.Error("Error getting absolute path", "error", err)
		os.Exit(1)
	}
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

	http.HandleFunc("/createnewcsr", HandleCreateNewCsr)
	http.HandleFunc("/uploadsignedcert", HandleUploadSignedCert)
	http.HandleFunc("/listcerts", HandleListCerts)

	http.ListenAndServe(hostnamePrivateApi, nil)

}
