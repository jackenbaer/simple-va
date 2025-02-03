package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func VerifyPrivateKeyMatchesCert(cert *x509.Certificate, privateKey *ecdsa.PrivateKey) (bool, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("certificate public key is not ECDSA")
	}
	if pub.Curve != privateKey.PublicKey.Curve ||
		pub.X.Cmp(privateKey.PublicKey.X) != 0 ||
		pub.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		return false, nil
	}
	return true, nil
}

func isValidOCSPSigning(cert *x509.Certificate) (bool, error) {

	// Check key usage
	hasDigitalSignature := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	hasOCSPSigning := false

	// Check extended key usage
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}

	// Return true if both conditions are met
	return hasDigitalSignature && hasOCSPSigning, nil

}

type OCSPResponder struct {
	OcspCert   *x509.Certificate
	IssuerCert *x509.Certificate
}

type Identity struct {
	PrivateKeyPath  string
	CertsFolderPath string
	privateKey      *ecdsa.PrivateKey
	ocspCerts       []string //pem encoded string
}

// TODO Remove this
func (i *Identity) GetPrivateKey() *ecdsa.PrivateKey {
	return i.privateKey
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
	files, err := ioutil.ReadDir(i.CertsFolderPath)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".pem" {
			filePath := filepath.Join(i.CertsFolderPath, file.Name())

			// Read file contents
			content, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			if len(content) == 0 {
				Logger.Warn("Skipping empty certificate file", "file", filePath)
				continue
			}

			//make sure the list stays unique
			for _, existingCert := range i.ocspCerts {
				if existingCert == string(content) {
					continue
				}
			}

			block, _ := pem.Decode([]byte(content))
			if block == nil {
				return fmt.Errorf("failed to store certs to files. unable to decode pem block of a certificate")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			keyMatchesCert, err := VerifyPrivateKeyMatchesCert(cert, i.privateKey)
			if err != nil {
				return err
			}
			if !keyMatchesCert {
				Logger.Error("Key does not match cert")
				continue
			}
			ocspCert, err := isValidOCSPSigning(cert)
			if err != nil {
				return err
			}
			if !ocspCert {
				Logger.Error("Not an OCSP Certificate")
				continue
			}
			i.ocspCerts = append(i.ocspCerts, string(content))
		}
	}
	return nil
}

func (i *Identity) AddOCSPCert(cert string) error {
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return fmt.Errorf("failed to store certs to files. unable to decode pem block of a certificate")
	}

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyMatchesCert, err := VerifyPrivateKeyMatchesCert(c, i.privateKey)
	if err != nil {
		return err
	}
	if !keyMatchesCert {
		return fmt.Errorf("Private key does not match cert")
	}
	ocspCert, err := isValidOCSPSigning(c)
	if err != nil {
		return err
	}
	if !ocspCert {
		return fmt.Errorf("Cert is not usable for ocsp signing")
	}

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
		filePath := filepath.Join(i.CertsFolderPath, filename)

		err = os.MkdirAll(i.CertsFolderPath, 0755)
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

	privateKeyFullpath := i.PrivateKeyPath

	_, err := os.Stat(privateKeyFullpath)
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

	Logger.Info("Key not found, generating a new ECDSA key...")

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
