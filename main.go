package main

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func handleOCSPRequest(w http.ResponseWriter, r *http.Request) {
	// Read the OCSP request from the incoming HTTP request
	reqBody := make([]byte, r.ContentLength)
	_, err := r.Body.Read(reqBody)
	if err != nil {
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode the OCSP request
	ocspRequest, err := base64.StdEncoding.DecodeString(string(reqBody))
	if err != nil {
		http.Error(w, "Invalid OCSP request format", http.StatusBadRequest)
		return
	}

	// Parse the OCSP request
	parsedRequest, err := ocsp.ParseRequest(ocspRequest)
	if err != nil {
		http.Error(w, "Failed to parse OCSP request", http.StatusBadRequest)
		return
	}

	// Here you would normally check the certificate status (revoked, valid, etc.)
	// For simplicity, we'll just create a "good" OCSP response
	// Construct a sample OCSP response
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: parsedRequest.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	// Normally, you would sign the response using a real private key and certificate
	response, err := ocsp.CreateResponse(
		nil,           // Issuer certificate (usually a CA certificate)
		responderCert, // Responder certificate (used to sign the OCSP response)
		template,      // OCSP response template
		crypto.SHA256, // Hash algorithm used for signing
	)
	if err != nil {
		http.Error(w, "Failed to create OCSP response", http.StatusInternalServerError)
		return
	}

	// Write the OCSP response to the client
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(response)

}

func main() {
	http.HandleFunc("/ocsp", handleOCSPRequest)
	log.Println("Starting OCSP Responder on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))

	// Load the responder certificate and private key
	certPath := "path/to/responder_cert.pem"
	keyPath := "path/to/responder_key.pem"

	cert, err := LoadResponderCert(certPath)
	if err != nil {
		log.Fatalf("Error loading responder certificate: %v", err)
	}
	fmt.Println("Responder certificate loaded successfully")

	privateKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		log.Fatalf("Error loading responder private key: %v", err)
	}
	fmt.Println("Responder private key loaded successfully")

}
