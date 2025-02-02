package kubelet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/config"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed kubeconfig.yaml
var _kubeconfig string

//go:embed kubelet-config.yaml
var _kubeletconfig string

type Kubelet interface {
	GetCurrentlyAppliedSpec() *config.KubernetesKubeletSpec
	ApplySpec(spec *config.KubernetesKubeletSpec) error
	CheckHealthy(context.Context) error
	GetStatus(ctx context.Context) (*config.KubernetesKubeletStatus, error)
	RestartService(context.Context) error
	AddCertificateForFulfillment(string, string)
	FulfillCertificate(string, string) error
}

func NewKubelet(
	nodeID string,
	kubeletPath string,
	launchScriptPath string,
	serviceSystemdName string,
	kubeletCaFile string,
	kubeletKubeletConfigFile string,
	kubeletKubeConfigFile string,
	kubeletCertFile string,
	kubeletKeyFile string,
	kubeProxyCertFile string,
) Kubelet {
	return &kubeletImpl{
		mutex:                    &sync.RWMutex{},
		nodeID:                   nodeID,
		kubeletPath:              kubeletPath,
		launchScriptPath:         launchScriptPath,
		serviceSystemdName:       serviceSystemdName,
		kubeletCaFile:            kubeletCaFile,
		kubeletKubeletConfigFile: kubeletKubeletConfigFile,
		kubeletKubeConfigFile:    kubeletKubeConfigFile,
		kubeletCertFile:          kubeletCertFile,
		kubeletKeyFile:           kubeletKeyFile,
		kubeProxyCertFile:        kubeProxyCertFile,
		currentlyAppliedSpec:     nil,
		lastRestart:              time.Unix(0, 0),
		sequenceNumber:           0,
		publicKey:                "",
		certificateFulfillment:   map[string]certFulfill{},
	}
}

type kubeletImpl struct {
	mutex                    *sync.RWMutex
	nodeID                   string
	kubeletPath              string
	launchScriptPath         string
	serviceSystemdName       string
	kubeletCaFile            string
	kubeletKubeletConfigFile string
	kubeletKubeConfigFile    string
	kubeletCertFile          string
	kubeletKeyFile           string
	kubeProxyCertFile        string
	currentlyAppliedSpec     *config.KubernetesKubeletSpec
	currentKubeconfigPath    string
	lastRestart              time.Time
	sequenceNumber           int
	publicKey                string
	certificateFulfillment   map[string]certFulfill
}

type certFulfill struct {
	certificate string
	notAfter    time.Time
}

func (k *kubeletImpl) GetCurrentlyAppliedSpec() *config.KubernetesKubeletSpec {
	k.mutex.RLock()
	defer k.mutex.RUnlock()
	return k.currentlyAppliedSpec
}

func (k *kubeletImpl) ApplySpec(spec *config.KubernetesKubeletSpec) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if !k.hasCertificateMounted() {
		return errors.New("certificate not mounted")
	}

	k.sequenceNumber = k.sequenceNumber + 1

	err := writeCertificatePEMs(k.kubeletCaFile, spec.CertificatePEMs)
	if err != nil {
		return err
	}

	kubeconfigPath := k.kubeletKubeConfigFile + "." + strconv.Itoa(k.sequenceNumber)

	launchScript, err := toKubeletLaunchScript(
		k.kubeletPath,
		spec,
		k.kubeletCaFile,
		k.kubeletKubeletConfigFile,
		kubeconfigPath,
		k.kubeletCertFile,
		k.kubeletKeyFile,
		k.sequenceNumber,
	)
	if err != nil {
		return err
	}

	err = os.WriteFile(k.launchScriptPath, []byte(launchScript), 0600)
	if err != nil {
		return err
	}
	k.currentlyAppliedSpec = spec
	k.currentKubeconfigPath = kubeconfigPath

	if k.sequenceNumber > 5 {
		k.sequenceNumber = 0
	}

	return nil
}

func (k *kubeletImpl) CheckHealthy(ctx context.Context) error {
	command := exec.CommandContext(ctx, "systemctl", "status", k.serviceSystemdName, "--no-pager")
	output, err := command.CombinedOutput()
	if err != nil {
		return err
	}
	if strings.Contains(string(output), "active (running)") || strings.Contains(string(output), "status=0/SUCCESS") {
		return nil
	}
	return errors.New(string(output))
}

func (k *kubeletImpl) RestartService(ctx context.Context) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	k.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", k.serviceSystemdName).Run()
}

func (k *kubeletImpl) GetStatus(ctx context.Context) (*config.KubernetesKubeletStatus, error) {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	publicKey, err := k.ensureKeyPair()
	if err != nil {
		return nil, err
	}

	var certificateRequest *config.KubernetesKubeletCertificateRequest
	if !k.hasCertificateMounted() {
		certificateRequest = &config.KubernetesKubeletCertificateRequest{
			PublicKey: publicKey,
		}
	}

	k.cleanupCerts()

	status := "HEALTHY"
	if err = k.CheckHealthy(ctx); err != nil {
		status = err.Error()
	}

	return &config.KubernetesKubeletStatus{
		CertificateRequest: certificateRequest,
		CertificateFulfill: toCertFulfill(k.certificateFulfillment),
		KubeconfigPath:     k.currentKubeconfigPath,
		Status:             status,
	}, nil
}

func (k *kubeletImpl) AddCertificateForFulfillment(nodeID string, certificate string) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.certificateFulfillment[nodeID] = certFulfill{
		certificate: certificate,
		notAfter:    time.Now().Add(time.Hour),
	}
}

func (k *kubeletImpl) FulfillCertificate(certificate string, certificateType string) error {
	if certificateType != "kubelet" && certificateType != "proxy" {
		return errors.New("invalid certificate type")
	}

	k.mutex.Lock()
	defer k.mutex.Unlock()

	der, err := base64.StdEncoding.DecodeString(certificate)
	if err != nil {
		return err
	}

	_, err = x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	path := k.kubeletCertFile
	if certificateType == "proxy" {
		path = k.kubeProxyCertFile
	}
	err = os.WriteFile(path, pemData, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (k *kubeletImpl) hasCertificateMounted() bool {
	_, err := os.ReadFile(k.kubeletCertFile)
	return err == nil
}

func (k *kubeletImpl) ensureKeyPair() (string, error) {
	if k.publicKey == "" {
		privateKeyBytes, err := os.ReadFile(k.kubeletKeyFile)
		if err != nil {
			if os.IsNotExist(err) {
				pk, err := generateKeyPair(k.kubeletKeyFile)
				if err != nil {
					return "", err
				}
				parsedPk, err := parsePublicKeyToString(pk)
				if err != nil {
					return "", err
				}
				k.publicKey = parsedPk
			}
			return "", err
		}
		pk, err := parseKeyPair(privateKeyBytes)
		if err != nil {
			return "", err
		}
		parsedPk, err := parsePublicKeyToString(pk)
		if err != nil {
			return "", err
		}
		k.publicKey = parsedPk
	}
	return k.publicKey, nil
}

func (k *kubeletImpl) cleanupCerts() {
	for id, entry := range k.certificateFulfillment {
		if time.Now().After(entry.notAfter) {
			delete(k.certificateFulfillment, id)
		}
	}
}

func toKubeletLaunchScript(
	kubeletPath string,
	spec *config.KubernetesKubeletSpec,
	caFile string,
	kubeletConfigFile string,
	kubeConfigFile string,
	certFile string,
	keyFile string,
	sequenceNumber int,
) (string, error) {
	kubeconfigContents, err := toKubeconfig(caFile, spec.APIServerAddress, certFile, keyFile)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(kubeConfigFile, []byte(kubeconfigContents), 0600)
	if err != nil {
		return "", err
	}

	kubeletConfigContents, err := toKubeletConfig(caFile, spec.APIServerAddress, certFile, keyFile, spec.KubeletAddress, spec.SecurePort, spec.ClusterDNS)
	if err != nil {
		return "", err
	}

	kubeletConfigPath := kubeletConfigFile + "." + strconv.Itoa(sequenceNumber)
	err = os.WriteFile(kubeletConfigPath, []byte(kubeletConfigContents), 0600)
	if err != nil {
		return "", err
	}

	args := map[string]string{}
	args["config"] = ""
	args["kubeconfig"] = kubeConfigFile
	args["config"] = kubeletConfigPath
	args["hostname-override"] = spec.Name + ".node.metal.local"
	var argStrings []string
	for key, value := range args {
		argStrings = append(argStrings, fmt.Sprintf("--%s=%s", key, value))
	}

	return kubeletPath + " " + strings.Join(argStrings, " "), nil
}

func parsePublicKeyToString(pk *rsa.PublicKey) (string, error) {
	return base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pk)), nil
}

func generateKeyPair(filePath string) (*rsa.PublicKey, error) {
	kubeletPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(kubeletPrivateKey)
	if err != nil {
		return nil, err
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	err = os.WriteFile(filePath, pemData, 0600)
	if err != nil {
		return nil, err
	}

	return &kubeletPrivateKey.PublicKey, nil
}

func parseKeyPair(keyContent []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyContent)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid rsa private key")
	}
	return &rsaKey.PublicKey, nil
}

func toCertFulfill(input map[string]certFulfill) map[string]string {
	result := map[string]string{}
	for k, v := range input {
		result[k] = v.certificate
	}
	return result
}

func toKubeletConfig(caFile string, serverAddress string, clientCertificate string, clientKey string, address string, port int, clusterDNS []string) (string, error) {
	kubeletconfig := _kubeletconfig

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$CA_DATA_PATH", fmt.Sprintf("\"%s\"", caFile))

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$SERVER_ADDRESS", fmt.Sprintf("\"%s\"", serverAddress))

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$CLIENT_CERTIFICATE_PATH", fmt.Sprintf("\"%s\"", clientCertificate))

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$CLIENT_KEY_PATH", fmt.Sprintf("\"%s\"", clientKey))

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$ADDRESS", fmt.Sprintf("\"%s\"", address))

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$PORT", strconv.Itoa(port))

	var clusterDNSStrings []string
	for _, entry := range clusterDNS {
		clusterDNSStrings = append(clusterDNSStrings, fmt.Sprintf("\"%s\"", entry))
	}

	kubeletconfig = strings.ReplaceAll(kubeletconfig, "$CLUSTER_DNS", strings.Join(clusterDNSStrings, ","))

	return kubeletconfig, nil
}

func toKubeconfig(caFile string, serverAddress string, clientCertificate string, clientKey string) (string, error) {
	kubeconfig := _kubeconfig

	kubeconfig = strings.ReplaceAll(kubeconfig, "$CA_DATA_PATH", fmt.Sprintf("\"%s\"", caFile))

	kubeconfig = strings.ReplaceAll(kubeconfig, "$SERVER_ADDRESS", fmt.Sprintf("\"%s\"", serverAddress))

	kubeconfig = strings.ReplaceAll(kubeconfig, "$CLIENT_CERTIFICATE_PATH", fmt.Sprintf("\"%s\"", clientCertificate))

	kubeconfig = strings.ReplaceAll(kubeconfig, "$CLIENT_KEY_PATH", fmt.Sprintf("\"%s\"", clientKey))

	return kubeconfig, nil
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
