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

	//TODO support more hash algorithmss
	fmt.Printf("hashalgorithm: %s\n", ocspReq.HashAlgorithm.String())

	issuerKeyHash := hex.EncodeToString(ocspReq.IssuerKeyHash[:])
	fmt.Printf("hash: %s\n", issuerKeyHash)

	issuerExists := ocspCertManager.IssuerExists(issuerKeyHash)

	entry, entryExists := CertStatus.GetEntry(issuerKeyHash, ocspReq.SerialNumber.String())

	var certStatus int
	if !entryExists && issuerExists { // cert is not revoked
		certStatus = ocsp.Good
		Logger.Info("OCSP status is good.",
			"IssuerKeyHash", issuerKeyHash,
			"SerialNumber", ocspReq.SerialNumber.String(),
		)
	} else if entryExists && issuerExists { // cert is revoked
		certStatus = ocsp.Revoked
		Logger.Info("OCSP status is revoked.",
			"IssuerKeyHash", issuerKeyHash,
			"ExpirationDate", entry.ExpirationDate,
			"RevocationDate", entry.RevocationDate,
			"RevocationReason", entry.RevocationReason,
			"SerialNumber", entry.SerialNumber,
		)

	} else if !entryExists && !issuerExists { // unkown issuer not controlled by this va
		Logger.Info("OCSP status is unkown. IssuerKeyHash not known",
			"IssuerKeyHash", issuerKeyHash)

		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ocsp.UnauthorizedErrorResponse)
		return
	}

	template := ocsp.Response{
		Status:       certStatus,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}
	value := ocspCertManager.responders[issuerKeyHash]
	issuerCert := value.IssuerCert
	responderCert := value.OcspCert

	// Create the OCSP response. The response is signed using the responder's key.
	ocspBytes, err := identity.CreateResponse(issuerCert, responderCert, template)
	if err != nil {
		http.Error(w, "Failed to create OCSP response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Write the OCSP response with the correct Content-Type.
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(ocspBytes)

}
