package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var identity *Identity

type createNewCsrRequest struct {
	CommonName string `json:"common_name"`
}

type createNewCsrResponse struct {
	CSR string `json:"csr"`
}

func HandleCreateNewCsr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Validation
	var req createNewCsrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validate the request (ensure CommonName is not empty)
	if req.CommonName == "" {
		http.Error(w, "CommonName is required", http.StatusBadRequest)
		return
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{"Example Organization"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrBytes, err := identity.CreateCsr(csrTemplate)
	if err != nil {
		http.Error(w, "CSR Generation Failed.", http.StatusBadRequest)
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	response := createNewCsrResponse{
		CSR: string(csrPEM),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

type UploadSignedCertRequest struct {
	Certificate string `json:"certificate"`
}

func HandleUploadSignedCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Validation
	var req UploadSignedCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	identity.AddOCSPCert(req.Certificate)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate uploaded successfully"))
}

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
	//Config
	hostnamePrivateApi := ":8080"
	identityFolder := "/tmp/"
	//hostnamePublicApi

	identityFolderPath, err := filepath.Abs(identityFolder)
	if err != nil {
		log.Fatalf("Error getting absolute path: %v", err)
	}
	err = ensurePathExists(identityFolderPath)
	if err != nil {
		log.Fatalf("Error ensuring that path exists: %v", err)
	}

	identity = &Identity{}
	err = identity.GetOrCreatePrivateKey(identityFolderPath)
	if err != nil {
		log.Fatalf("Failed to get or create private key: %v", err)
	}

	http.HandleFunc("/createnewcsr", HandleCreateNewCsr)
	http.HandleFunc("/uploadsignedcert", HandleUploadSignedCert)

	http.ListenAndServe(hostnamePrivateApi, nil)
}
