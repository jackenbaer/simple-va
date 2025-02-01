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

/*
	func ocspHandler(w http.ResponseWriter, r *http.Request) {
		// Only allow POST requests.
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Validate that the Content-Type is "application/ocsp-request".
		if r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "Invalid Content-Type; expected application/ocsp-request", http.StatusBadRequest)
			return
		}

		// Read the request body (DER-encoded OCSP request).
		reqBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Parse the OCSP request.
		ocspReq, err := ocsp.ParseRequest(reqBytes)
		if err != nil {
			http.Error(w, "Invalid OCSP request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// For demonstration purposes, we assume the certificate status is "good".
		// In a real implementation, you would check ocspReq.SerialNumber against your revocation data.
		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}

		// Create the OCSP response. The response is signed using the responder's key.
		ocspBytes, err := ocsp.CreateResponse(issuerCert, responderCert, template, responderKey)
		if err != nil {
			http.Error(w, "Failed to create OCSP response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Write the OCSP response with the correct Content-Type.
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(ocspBytes)
	}

	func StartPublicListener() {
		http.HandleFunc("/ocsp", ocspHandler)
		log.Fatal(http.ListenAndServe(":8080", nil))
	}
*/
func StartPrivateApiListener(hostnamePrivateApi *url.URL) {
	http.HandleFunc("/createnewcsr", HandleCreateNewCsr)
	http.HandleFunc("/uploadsignedcert", HandleUploadSignedCert)
	http.HandleFunc("/listcerts", HandleListCerts)

	err := http.ListenAndServe(hostnamePrivateApi.String(), nil)
	if err != nil {
		Logger.Error("Error starting private API listener")
		os.Exit(1)
	}

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
	identityFolder := "."
	//hostnamePublicApi

	//Check Config
	parsedURL, err := url.Parse(hostnamePrivateApi)
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
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

	go StartPrivateApiListener(parsedURL)
}
