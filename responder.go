package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Function to load the responder certificate from a PEM file
func LoadResponderCert(certPath string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// Function to load the private key from a PEM file
func LoadPrivateKey(keyPath string) (crypto.Signer, error) {
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the private key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
		}
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a crypto.Signer")
	}

	return signer, nil
}
