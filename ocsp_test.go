package ocsp_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"testing"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPRequest(t *testing.T) {
	// Load the certificate and issuer certificate
	certPEM := `-----BEGIN CERTIFICATE-----
MIID...YourCertHere...-----END CERTIFICATE-----`
	issuerPEM := `-----BEGIN CERTIFICATE-----
MIID...YourIssuerCertHere...-----END CERTIFICATE-----`

	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		t.Fatalf("Failed to decode certificate PEM")
	}
	issuerBlock, _ := pem.Decode([]byte(issuerPEM))
	if issuerBlock == nil {
		t.Fatalf("Failed to decode issuer certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse issuer certificate: %v", err)
	}

	// Create the OCSP request
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Fatalf("Failed to create OCSP request: %v", err)
	}

	// The OCSP server URL should be provided in the certificate
	if len(cert.OCSPServer) == 0 {
		t.Fatalf("Certificate does not contain an OCSP server URL")
	}

	ocspURL := cert.OCSPServer[0]

	// Send the OCSP request
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		t.Fatalf("Failed to send OCSP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected HTTP status code: %d", resp.StatusCode)
	}

	// Parse the OCSP response
	ocspResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read OCSP response: %v", err)
	}

	parsedResponse, err := ocsp.ParseResponse(ocspResponse, issuer)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// Validate the response status
	switch parsedResponse.Status {
	case ocsp.Good:
		t.Log("Certificate status: Good")
	case ocsp.Revoked:
		t.Fatalf("Certificate status: Revoked")
	case ocsp.Unknown:
		t.Fatalf("Certificate status: Unknown")
	default:
		t.Fatalf("Unrecognized OCSP status: %v", parsedResponse.Status)
	}
}
