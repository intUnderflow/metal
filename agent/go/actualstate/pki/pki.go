package pki

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

type PKI interface {
	GetRootCA() string
	GetServiceAccountPublicKey() (string, error)
	GetServiceAccountPrivateKey() (string, error)
	GetEncryptionKey() string
	IssueAPIServerCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error)
	IssueKubeControllerManagerCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error)
	IssueKubeSchedulerCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error)
	IssueSuperAdminCertificate(commonName string, publicKey crypto.PublicKey) ([]byte, error)
	IssueKubeNodeCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error)
}

func NewPKI(caPath string, nameConstraint string) (PKI, error) {
	content, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return generatePKI(caPath, nameConstraint)
		}
		return nil, err
	}
	return parsePKI(content)
}

func NewPKIFromExisting(caPath string) (PKI, error) {
	content, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	return parsePKI(content)
}

func generatePKI(caPath string, nameConstraint string) (PKI, error) {
	sn := generateSerialNumber()
	ca := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			SerialNumber: sn.String(),
			CommonName:   nameConstraint,
		},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         append(_extraDNSNames, nameConstraint),
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().AddDate(10, 0, 0),
		IsCA:                        true,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
	}

	caPublicKey, caPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	serviceAccountPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	if err != nil {
		return nil, err
	}
	encryptionKeyString := base64.StdEncoding.EncodeToString(encryptionKey)

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}

	caPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(caPrivateKey)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: caPrivKeyBytes,
	})
	if err != nil {
		return nil, err
	}

	serviceAccountPrivateKeyBytes, err := x509.MarshalPKCS8PrivateKey(serviceAccountPrivateKey)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "RSA SERVICE ACCOUNT PRIVATE KEY",
		Bytes: serviceAccountPrivateKeyBytes,
	})
	if err != nil {
		return nil, err
	}

	err = pem.Encode(caPEM, &pem.Block{
		Type:  "ENCRYPTION CONFIG SECRET",
		Bytes: encryptionKey,
	})
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(caPath, caPEM.Bytes(), 0600)
	if err != nil {
		return nil, err
	}

	return &pkiImpl{
		ca:                       ca,
		caDER:                    caBytes,
		privateKey:               caPrivateKey,
		serviceAccountPrivateKey: serviceAccountPrivateKey,
		encryptionKey:            encryptionKeyString,
	}, nil
}

func parsePKI(content []byte) (PKI, error) {
	var certificate *x509.Certificate
	var certificateDER []byte
	var privateKey ed25519.PrivateKey
	var serviceAccountPrivateKey *rsa.PrivateKey
	var encryptionConfigSecret []byte
	current := content
	for {
		block, rest := pem.Decode(current)
		if block == nil {
			break
		}
		current = rest

		if block.Type == "CERTIFICATE" {
			certificateDER = block.Bytes
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certificate = cert
		} else if block.Type == "ED25519 PRIVATE KEY" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			edKey, ok := key.(ed25519.PrivateKey)
			if !ok {
				return nil, errors.New("invalid ed25519 private key")
			}
			privateKey = edKey
		} else if block.Type == "RSA SERVICE ACCOUNT PRIVATE KEY" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("invalid rsa private key")
			}
			serviceAccountPrivateKey = rsaKey
		} else if block.Type == "ENCRYPTION CONFIG SECRET" {
			encryptionConfigSecret = block.Bytes
		}
	}

	if certificate == nil {
		return nil, errors.New("no certificate")
	}
	if privateKey == nil {
		return nil, errors.New("no private key")
	}
	if serviceAccountPrivateKey == nil {
		return nil, errors.New("no service account private key")
	}

	return &pkiImpl{
		ca:                       certificate,
		caDER:                    certificateDER,
		privateKey:               privateKey,
		serviceAccountPrivateKey: serviceAccountPrivateKey,
		encryptionKey:            base64.StdEncoding.EncodeToString(encryptionConfigSecret),
	}, nil
}

type pkiImpl struct {
	ca                       *x509.Certificate
	caDER                    []byte
	privateKey               ed25519.PrivateKey
	serviceAccountPrivateKey *rsa.PrivateKey
	encryptionKey            string
}

func (p *pkiImpl) GetRootCA() string {
	return base64.StdEncoding.EncodeToString(p.caDER)
}

func (p *pkiImpl) GetServiceAccountPublicKey() (string, error) {
	publicKey := &p.serviceAccountPrivateKey.PublicKey
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func (p *pkiImpl) GetServiceAccountPrivateKey() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(p.serviceAccountPrivateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func (p *pkiImpl) GetEncryptionKey() string {
	return p.encryptionKey
}

func (p *pkiImpl) IssueAPIServerCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error) {
	sn := generateSerialNumber()
	apiServerCert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			SerialNumber: sn.String(),
			CommonName:   nodeName + ".node.metal.local",
		},
		DNSNames: []string{
			nodeName + ".node.metal.local",
			"kubernetes",
			"kubernetes.default",
			"kubernetes.default.svc",
			"kubernetes.default.svc.cluster",
			"kubernetes.default.svc.cluster.local",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		Issuer:      p.ca.Subject,
	}

	cert, err := x509.CreateCertificate(rand.Reader, apiServerCert, p.ca, publicKey, p.privateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (p *pkiImpl) IssueKubeControllerManagerCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error) {
	sn := generateSerialNumber()
	controllerManagerCert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			SerialNumber: sn.String(),
			CommonName:   "system:kube-controller-manager",
		},
		DNSNames: []string{
			"kube-controller-manager." + nodeName + ".node.metal.local",
			"kube-proxy",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		Issuer:      p.ca.Subject,
	}

	cert, err := x509.CreateCertificate(rand.Reader, controllerManagerCert, p.ca, publicKey, p.privateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (p *pkiImpl) IssueKubeSchedulerCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error) {
	sn := generateSerialNumber()
	schedulerCert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			SerialNumber: sn.String(),
			CommonName:   "system:kube-scheduler",
		},
		DNSNames: []string{
			"kube-scheduler." + nodeName + ".node.metal.local",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		Issuer:      p.ca.Subject,
	}

	cert, err := x509.CreateCertificate(rand.Reader, schedulerCert, p.ca, publicKey, p.privateKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (p *pkiImpl) IssueSuperAdminCertificate(commonName string, publicKey crypto.PublicKey) ([]byte, error) {
	sn := generateSerialNumber()
	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			SerialNumber: sn.String(),
			CommonName:   commonName,
			Organization: []string{
				"system:masters",
			},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		Issuer:      p.ca.Subject,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, p.ca, publicKey, p.privateKey)
	if err != nil {
		return nil, err
	}

	return certBytes, nil
}

func (p *pkiImpl) IssueKubeNodeCertificate(nodeName string, publicKey crypto.PublicKey) ([]byte, error) {
	sn := generateSerialNumber()
	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			SerialNumber: sn.String(),
			CommonName:   fmt.Sprintf("system:node:%s.node.metal.local", nodeName),
			Organization: []string{
				"system:nodes",
			},
		},
		DNSNames: []string{
			fmt.Sprintf("%s.node.metal.local", nodeName),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		Issuer:      p.ca.Subject,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, p.ca, publicKey, p.privateKey)
	if err != nil {
		return nil, err
	}

	return certBytes, nil
}

func generateSerialNumber() *big.Int {
	maxSerialNumber := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, maxSerialNumber)
	return serialNumber
}
