package pki

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

var (
	_extraDNSNames = []string{
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster",
		"kubernetes.default.svc.cluster.local",
		"kube-proxy",
	}
)

func VerifyRootCertificateConformity(certificatePEM string, nameConstraint string) error {
	certificateDER, err := base64.StdEncoding.DecodeString(certificatePEM)
	if err != nil {
		return err
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return err
	}

	if !certificate.PermittedDNSDomainsCritical {
		return fmt.Errorf("root certificate permitted DNS domains is not marked as critical")
	}

	return verifyCertificateCommon(certificate.PermittedDNSDomains, nameConstraint)
}

func VerifyLeafCertificateConformity(certificatePEM string, nameConstraint string) error {
	certificateDER, err := base64.StdEncoding.DecodeString(certificatePEM)
	if err != nil {
		return err
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return err
	}

	return verifyCertificateCommon(certificate.DNSNames, nameConstraint)
}

func VerifyPublicKeyWellFormed(publicKey string) error {
	der, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}

	_, err = x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}
	return nil
}

func verifyCertificateCommon(certificateNames []string, nameConstraint string) error {
	permittedSANsAndSubjects := append(_extraDNSNames, nameConstraint)
	permittedSANsAndSubjectsMap := map[string]bool{}
	for _, entry := range permittedSANsAndSubjects {
		permittedSANsAndSubjectsMap[entry] = true
	}

	for _, entry := range certificateNames {
		if _, ok := permittedSANsAndSubjectsMap[entry]; !ok {
			return fmt.Errorf("certificate contains a DNS name which is out of conformance: %s, in conformance: %s", entry, strings.Join(permittedSANsAndSubjects, ","))
		}
	}

	return nil
}
