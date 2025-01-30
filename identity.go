package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Identity struct {
	FolderPath string
	privateKey *ecdsa.PrivateKey
	ocspCerts  []string //pem encoded string
}

func (i *Identity) Init() error {
	err := i.getOrCreatePrivateKey()
	if err != nil {
		return err
	}
	err = i.getCerts()
	if err != nil {
		return err
	}
	return nil
}

func (i *Identity) getCerts() error {
	files, err := ioutil.ReadDir(i.FolderPath)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".pem" {
			filePath := filepath.Join(i.FolderPath, file.Name())

			// Read file contents
			content, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			//make sure the list stays unique
			for _, existingCert := range i.ocspCerts {
				if existingCert == string(content) {
					continue
				}
			}

			// Append certificate content to the slice
			i.ocspCerts = append(i.ocspCerts, string(content))
		}
	}
	return nil
}

func (i *Identity) AddOCSPCert(cert string) error {
	for _, existingCert := range i.ocspCerts {
		if existingCert == cert {
			return nil
		}
	}
	i.ocspCerts = append(i.ocspCerts, cert)

	for _, pemCert := range i.ocspCerts {
		block, _ := pem.Decode([]byte(pemCert))
		if block == nil {
			return fmt.Errorf("failed to store certs to files. unable to decode pem block of a certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		sha256Fingerprint := sha256.Sum256(cert.Raw)
		fingerprintHex := hex.EncodeToString(sha256Fingerprint[:])

		filename := fmt.Sprintf("%s.pem", fingerprintHex)
		filePath := filepath.Join(filepath.Join(i.FolderPath, "certs"), filename)

		err = os.MkdirAll(filepath.Join(i.FolderPath, "certs"), 0755)
		if err != nil {
			return err
		}

		err = os.WriteFile(filePath, []byte(pemCert), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *Identity) ListOCSPCerts() []string {
	return i.ocspCerts
}

func (i *Identity) GetPublicKey() (*ecdsa.PublicKey, error) {
	if i.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}

	return &i.privateKey.PublicKey, nil
}

func (i *Identity) getOrCreatePrivateKey() error {
	const privateKeyFilename = "priv.pem"

	err := os.MkdirAll(i.FolderPath, 0755)
	if err != nil {
		return err
	}

	privateKeyFullpath := filepath.Join(i.FolderPath, privateKeyFilename)

	_, err = os.Stat(privateKeyFullpath)
	if err == nil {
		data, err := os.ReadFile(privateKeyFullpath)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block from %s", privateKeyFullpath)
		}

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		i.privateKey = key
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	fmt.Println("Key not found, generating a new ECDSA key...")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.Create(privateKeyFullpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	i.privateKey = key

	return nil
}

func (i *Identity) CreateCsr(csrTemplate *x509.CertificateRequest) ([]byte, error) {
	if i.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, i.privateKey)
	if err != nil {
		return []byte{}, err
	}
	return csrBytes, nil
}
