package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func HandleOcsp(w http.ResponseWriter, r *http.Request) {
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
	fmt.Printf("OCSP Request: %v", ocspReq)

	// For demonstration purposes, we assume the certificate status is "good".
	// In a real implementation, you would check ocspReq.SerialNumber against your revocation data.
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	//TODO support more hash algorithmss
	fmt.Printf("hashalgorithm: %s\n", ocspReq.HashAlgorithm.String())

	k := hex.EncodeToString(ocspReq.IssuerKeyHash[:])
	fmt.Printf("hash: %s\n", k)

	// Check if the key exists
	if value, exists := responderMap[k]; exists {
		fmt.Println("Key exists! Value:", value)
		issuerCert := value.IssuerCert
		responderCert := value.OcspCert
		responderKey := identity.GetPrivateKey()
		// Create the OCSP response. The response is signed using the responder's key.
		ocspBytes, err := ocsp.CreateResponse(issuerCert, responderCert, template, responderKey)
		if err != nil {
			http.Error(w, "Failed to create OCSP response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Write the OCSP response with the correct Content-Type.
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(ocspBytes)

	} else {
		fmt.Println("Key does not exist.")
	}

}
