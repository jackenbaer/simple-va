package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParseCSRFromPEM(pemString string) (*x509.CertificateRequest, error) {
	// Decode the PEM block.
	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate request")
	}

	// Parse the DER-encoded certificate request.
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}

	return csr, nil
}
func CSRToPEM(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})
}

func CertToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func KeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}
func PemToCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

func PemToCrl(pemData string) (*x509.RevocationList, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "X509 CRL" {
		return nil, errors.New("failed to decode PEM block containing a CRL")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing CRL: %w", err)
	}
	return crl, nil
}
