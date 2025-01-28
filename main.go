package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
)

type CreateNewIdentityRequest struct {
	CommonName string `json:"common_name"`
}

type CreateNewIdentityResponse struct {
	CSR string `json:"csr"`
}

func GenerateOCSPCert(commonName string) (privateKeyBytes []byte, csrBytes []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Example Organization"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrBytes, err = x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	privateKeyBytes, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	return privateKeyBytes, csrBytes, nil
}

func createNewIdentityHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode the JSON request body into CreateNewIdentityRequest
	var req CreateNewIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validate the request (ensure CommonName is not empty)
	if req.CommonName == "" {
		http.Error(w, "CommonName is required", http.StatusBadRequest)
		return
	}

	_, csrBytes, err := GenerateOCSPCert(req.CommonName)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	response := CreateNewIdentityResponse{
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

func main() {
	hostnamePrivateApi := ":8080"

	http.HandleFunc("/createnewidentity", createNewIdentityHandler)

	http.ListenAndServe(hostnamePrivateApi, nil)
}
