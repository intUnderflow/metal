package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Verifier interface {
	// Verify verifies a given Signature applies to a given Signable, the string argument is the required subject name
	// prefix . The suffix is always checked and has to be .metal.local.
	// for example, if the required prefix is "admin-" the subject must be something like admin-1.metal.local
	Verify(*Signature, Signable, string) error
}

type pKIVerifier struct {
	rootCA *x509.CertPool
}

func (p *pKIVerifier) Verify(signature *Signature, signable Signable, requiredSuffix string) error {
	forSignature, err := signable.ContentsForSignature()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(signature.X509CertificatePEM))
	if block == nil {
		return errors.New("certified PEM is not a valid PEM")
	}

	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("expected a PEM block of type certificate, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(cert.Subject.CommonName, requiredSuffix) {
		return fmt.Errorf("certificate common name does not end with suffix %s, the CN is %s", requiredSuffix, cert.Subject.CommonName)
	}

	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate must have an RSA public key")
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: p.rootCA,
	})
	if err != nil {
		return err
	}

	signaturesBytes, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil {
		return err
	}

	forSignatureHash := sha512.Sum512(forSignature)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA512, forSignatureHash[:], signaturesBytes)
	if err != nil {
		return err
	}

	return nil
}

func PKIVerifierFromFile(rootCAPath string) (Verifier, error) {
	certPool, err := LoadCertPoolFromFile(rootCAPath)
	if err != nil {
		return nil, err
	}

	return &pKIVerifier{
		rootCA: certPool,
	}, nil
}

func LoadCertPoolFromFile(certFile string) (*x509.CertPool, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	certPool := x509.NewCertPool()

	var block *pem.Block
	for {
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}

		certPool.AddCert(cert)
	}

	return certPool, nil
}
