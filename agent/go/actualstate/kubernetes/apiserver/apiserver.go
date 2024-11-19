package apiserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
	"github.com/intunderflow/metal/config"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed encryption-config.yaml
var _encryptionConfig string

type ApiServer interface {
	GetCurrentlyAppliedSpec() *config.KubernetesAPIServerSpec
	ApplySpec(spec *config.KubernetesAPIServerSpec) error
	CheckHealthy(context.Context) error
	RestartService(context.Context) error
}

type apiServerImpl struct {
	mutex                        *sync.RWMutex
	pkiService                   pki.PKI
	nodeID                       string
	apiServerPath                string
	launchScriptPath             string
	serviceSystemdName           string
	serviceAccountSigningKeyFile string
	serviceAccountKeyFile        string
	caFile                       string
	apiServerCertFile            string
	apiServerKeyFile             string
	encryptionConfigFile         string
	currentlyAppliedSpec         *config.KubernetesAPIServerSpec
	lastRestart                  time.Time
}

func NewApiServer(
	pkiService pki.PKI,
	nodeID string,
	apiServerPath string,
	launchScriptPath string,
	serviceSystemdName string,
	serviceAccountSigningKeyFile string,
	serviceAccountKeyFile string,
	caFile string,
	apiServerCertFile string,
	apiServerKeyFile string,
	encryptionConfigFile string,
) ApiServer {
	return &apiServerImpl{
		mutex:                        &sync.RWMutex{},
		pkiService:                   pkiService,
		nodeID:                       nodeID,
		apiServerPath:                apiServerPath,
		launchScriptPath:             launchScriptPath,
		serviceSystemdName:           serviceSystemdName,
		serviceAccountSigningKeyFile: serviceAccountSigningKeyFile,
		serviceAccountKeyFile:        serviceAccountKeyFile,
		caFile:                       caFile,
		apiServerCertFile:            apiServerCertFile,
		apiServerKeyFile:             apiServerKeyFile,
		encryptionConfigFile:         encryptionConfigFile,
		currentlyAppliedSpec:         nil,
		lastRestart:                  time.Unix(0, 0),
	}
}

func (a *apiServerImpl) GetCurrentlyAppliedSpec() *config.KubernetesAPIServerSpec {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.currentlyAppliedSpec
}

func (a *apiServerImpl) ApplySpec(spec *config.KubernetesAPIServerSpec) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	err := a.ensureCrypto()
	if err != nil {
		return err
	}

	err = writeCertificatePEMs(a.caFile, spec.CertificatePEMs)
	if err != nil {
		return err
	}

	err = writePublicKeyPEMs(a.serviceAccountKeyFile, spec.ServiceAccountPublicKeyPEMs)
	if err != nil {
		return err
	}

	privateKey, err := a.pkiService.GetServiceAccountPrivateKey()
	if err != nil {
		return err
	}

	err = writePrivateKeyPEM(a.serviceAccountSigningKeyFile, privateKey)
	if err != nil {
		return err
	}

	err = writeEncryptionConfig(a.encryptionConfigFile, a.pkiService.GetEncryptionKey())
	if err != nil {
		return err
	}

	launchScript := toApiServerLaunchScript(
		a.apiServerPath,
		spec,
		a.serviceAccountSigningKeyFile,
		a.serviceAccountKeyFile,
		a.caFile,
		a.apiServerCertFile,
		a.apiServerKeyFile,
	)
	err = os.WriteFile(a.launchScriptPath, []byte(launchScript), 0600)
	if err != nil {
		return err
	}
	a.currentlyAppliedSpec = spec
	return nil
}

func (a *apiServerImpl) CheckHealthy(ctx context.Context) error {
	command := exec.CommandContext(ctx, "systemctl", "status", a.serviceSystemdName, "--no-pager")
	output, err := command.CombinedOutput()
	if err != nil {
		return err
	}
	if strings.Contains(string(output), "active (running)") || strings.Contains(string(output), "status=0/SUCCESS") {
		return nil
	}
	return errors.New(string(output))
}

func (a *apiServerImpl) RestartService(ctx context.Context) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	a.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", a.serviceSystemdName).Run()
}

func (a *apiServerImpl) ensureCrypto() error {
	var apiServerCertificate []byte
	var err error
	if _, err = os.ReadFile(a.apiServerCertFile); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		marshalledKey, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		apiServerCertificate, err = a.pkiService.IssueAPIServerCertificate(a.nodeID, &key.PublicKey)
		if err != nil {
			return err
		}

		err = os.WriteFile(a.apiServerCertFile, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: apiServerCertificate,
		}), 0600)
		if err != nil {
			return err
		}
		err = os.WriteFile(a.apiServerKeyFile, pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: marshalledKey,
		}), 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeEncryptionConfig(encryptionConfigPath string, secret string) error {
	configContents := strings.ReplaceAll(_encryptionConfig, "$KEY", secret)

	err := os.WriteFile(encryptionConfigPath, []byte(configContents), 0600)
	if err != nil {
		return err
	}
	return nil
}

func writePrivateKeyPEM(privateKeyPath string, privateKeyPEM string) error {
	pemBuffer := &bytes.Buffer{}

	der, err := base64.StdEncoding.DecodeString(privateKeyPEM)
	if err != nil {
		return err
	}

	err = pem.Encode(pemBuffer, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	if err != nil {
		return err
	}

	err = os.WriteFile(privateKeyPath, pemBuffer.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}

func writePublicKeyPEMs(publicKeyPath string, pems map[string]string) error {
	pemBuffer := &bytes.Buffer{}

	for _, publicKey := range pems {
		der, err := base64.StdEncoding.DecodeString(publicKey)
		if err != nil {
			return err
		}
		err = pem.Encode(pemBuffer, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})
		if err != nil {
			return err
		}
	}

	err := os.WriteFile(publicKeyPath, pemBuffer.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}

func writeCertificatePEMs(caPath string, pems map[string]string) error {
	pemBuffer := &bytes.Buffer{}

	for _, cert := range pems {
		der, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return err
		}
		err = pem.Encode(pemBuffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})
		if err != nil {
			return err
		}
	}

	err := os.WriteFile(caPath, pemBuffer.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}

func toApiServerLaunchScript(
	binaryPath string,
	spec *config.KubernetesAPIServerSpec,
	serviceAccountSigningKeyFile string,
	serviceAccountKeyFile string,
	caFile string,
	apiServerCertFile string,
	apiServerKeyFile string,
) string {
	args := map[string]string{}
	args["advertise-address"] = spec.AdvertiseAddress
	args["etcd-servers"] = strings.Join(spec.EtcdServers, ",")
	args["service-cluster-ip-range"] = "10.96.0.0/12"
	args["service-node-port-range"] = "30000-32767"
	args["authorization-mode"] = "Node,RBAC"
	args["bind-address"] = spec.AdvertiseAddress
	args["enable-admission-plugins"] = "NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota"
	args["event-ttl"] = "1h"
	args["runtime-config"] = "api/all=true"
	args["service-account-issuer"] = fmt.Sprintf("https://kubernetes:%d", spec.SecurePort)
	args["api-audiences"] = "api"
	args["service-account-signing-key-file"] = serviceAccountSigningKeyFile
	args["service-account-key-file"] = serviceAccountKeyFile
	args["client-ca-file"] = caFile
	args["kubelet-certificate-authority"] = caFile
	args["kubelet-client-certificate"] = apiServerCertFile
	args["kubelet-client-key"] = apiServerKeyFile
	args["tls-cert-file"] = apiServerCertFile
	args["tls-private-key-file"] = apiServerKeyFile
	args["secure-port"] = strconv.Itoa(spec.SecurePort)
	args["requestheader-client-ca-file"] = caFile
	args["requestheader-allowed-names"] = ""
	args["requestheader-extra-headers-prefix"] = "X-Remote-Extra-"
	args["requestheader-group-headers"] = "X-Remote-Group"
	args["requestheader-username-headers"] = "X-Remote-User"
	// Feature: UnknownVersionInteroperabilityProxy + StorageVersionAPI
	// args["peer-advertise-ip"] = spec.AdvertiseAddress
	// args["peer-advertise-port"] = strconv.Itoa(spec.SecurePort)
	// args["peer-ca-file"] = caFile

	var featureGates []string
	for feature, enabled := range spec.FeatureGates {
		featureGates = append(featureGates, fmt.Sprintf("%s=%s", feature, toFeatureGateStatus(enabled)))
	}
	if len(featureGates) > 0 {
		args["feature-gates"] = strings.Join(featureGates, ",")
	}

	var argStrings []string
	for key, value := range args {
		argStrings = append(argStrings, fmt.Sprintf("--%s=%s", key, value))
	}

	return binaryPath + " " + strings.Join(argStrings, " ")
}

func toFeatureGateStatus(status bool) string {
	if status {
		return "true"
	}
	return "false"
}
