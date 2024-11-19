package controller_manager

import (
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

//go:embed kubeconfig.yaml
var _kubeconfig string

type ControllerManager interface {
	GetCurrentlyAppliedSpec() *config.KubernetesControllerManagerSpec
	ApplySpec(*config.KubernetesControllerManagerSpec) error
	CheckHealthy(context.Context) error
	RestartService(context.Context) error
}

type controllerManagerImpl struct {
	mutex                           *sync.RWMutex
	pkiService                      pki.PKI
	nodeID                          string
	controllerManagerPath           string
	launchScriptPath                string
	serviceSystemdName              string
	caFile                          string
	controllerManagerKubeConfigFile string
	controllerManagerCertFile       string
	controllerManagerKeyFile        string
	currentlyAppliedSpec            *config.KubernetesControllerManagerSpec
	lastRestart                     time.Time
	sequenceNumber                  int
}

func NewControllerManager(
	pkiService pki.PKI,
	nodeID string,
	controllerManagerPath string,
	launchScriptPath string,
	caFile string,
	serviceSystemdName string,
	controllerManagerKubeConfigFile string,
	controllerManagerCertFile string,
	controllerManagerKeyFile string,
) ControllerManager {
	return &controllerManagerImpl{
		mutex:                           &sync.RWMutex{},
		pkiService:                      pkiService,
		nodeID:                          nodeID,
		controllerManagerPath:           controllerManagerPath,
		launchScriptPath:                launchScriptPath,
		caFile:                          caFile,
		serviceSystemdName:              serviceSystemdName,
		controllerManagerKubeConfigFile: controllerManagerKubeConfigFile,
		controllerManagerCertFile:       controllerManagerCertFile,
		controllerManagerKeyFile:        controllerManagerKeyFile,
		currentlyAppliedSpec:            nil,
		lastRestart:                     time.Unix(0, 0),
	}
}

func (c *controllerManagerImpl) GetCurrentlyAppliedSpec() *config.KubernetesControllerManagerSpec {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.currentlyAppliedSpec
}

func (c *controllerManagerImpl) ApplySpec(spec *config.KubernetesControllerManagerSpec) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	err := c.ensureCrypto()
	if err != nil {
		return err
	}

	c.sequenceNumber = c.sequenceNumber + 1

	launchScript, err := toControllerManagerLaunchScript(
		c.controllerManagerPath,
		spec,
		c.caFile,
		c.controllerManagerKubeConfigFile,
		c.controllerManagerCertFile,
		c.controllerManagerKeyFile,
		c.sequenceNumber,
	)
	if err != nil {
		return err
	}

	err = os.WriteFile(c.launchScriptPath, []byte(launchScript), 0600)
	if err != nil {
		return err
	}
	c.currentlyAppliedSpec = spec

	if c.sequenceNumber > 5 {
		c.sequenceNumber = 0
	}

	return nil
}

func (c *controllerManagerImpl) CheckHealthy(ctx context.Context) error {
	command := exec.CommandContext(ctx, "systemctl", "status", c.serviceSystemdName, "--no-pager")
	output, err := command.CombinedOutput()
	if err != nil {
		return err
	}
	if strings.Contains(string(output), "active (running)") || strings.Contains(string(output), "status=0/SUCCESS") {
		return nil
	}
	return errors.New(string(output))
}

func (c *controllerManagerImpl) RestartService(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	c.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", c.serviceSystemdName).Run()
}

func (c *controllerManagerImpl) ensureCrypto() error {
	var certificate []byte
	var err error
	if _, err = os.ReadFile(c.controllerManagerCertFile); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		marshalledKey, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		certificate, err = c.pkiService.IssueKubeControllerManagerCertificate(c.nodeID, &key.PublicKey)
		if err != nil {
			return err
		}

		err = os.WriteFile(c.controllerManagerCertFile, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate,
		}), 0600)
		if err != nil {
			return err
		}
		err = os.WriteFile(c.controllerManagerKeyFile, pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: marshalledKey,
		}), 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func toControllerManagerLaunchScript(
	binaryPath string,
	spec *config.KubernetesControllerManagerSpec,
	caFile string,
	controllerManagerKubeConfigFile string,
	controllerManagerCertFile string,
	controllerManagerKeyFile string,
	sequenceNumber int,
) (string, error) {
	kubeconfigContents, err := toKubeconfig(caFile, spec.ServerAddress, controllerManagerCertFile, controllerManagerKeyFile)
	if err != nil {
		return "", err
	}

	kubeconfigPath := controllerManagerKubeConfigFile + "." + strconv.Itoa(sequenceNumber)
	err = os.WriteFile(kubeconfigPath, []byte(kubeconfigContents), 0600)
	if err != nil {
		return "", err
	}

	args := map[string]string{}
	args["bind-address"] = spec.AdvertiseAddress
	args["secure-port"] = strconv.Itoa(spec.SecurePort)
	args["service-cluster-ip-range"] = "10.96.0.0/12"
	args["cluster-cidr"] = spec.ClusterCIDR
	args["use-service-account-credentials"] = "true"
	args["cluster-name"] = "kubernetes"
	args["root-ca-file"] = caFile
	args["cluster-signing-cert-file"] = controllerManagerCertFile
	args["cluster-signing-key-file"] = controllerManagerKeyFile
	args["kubeconfig"] = kubeconfigPath
	args["authentication-kubeconfig"] = kubeconfigPath
	args["authorization-kubeconfig"] = kubeconfigPath
	args["v"] = "2"

	var argStrings []string
	for key, value := range args {
		argStrings = append(argStrings, fmt.Sprintf("--%s=%s", key, value))
	}

	return binaryPath + " " + strings.Join(argStrings, " "), nil
}

func toKubeconfig(caFile string, serverAddress string, clientCertificate string, clientKey string) (string, error) {
	kubeconfig := _kubeconfig

	caData, err := os.ReadFile(caFile)
	if err != nil {
		return "", err
	}
	kubeconfig = strings.ReplaceAll(kubeconfig, "$CA_DATA", base64.StdEncoding.EncodeToString(caData))

	kubeconfig = strings.ReplaceAll(kubeconfig, "$SERVER_ADDRESS", fmt.Sprintf("\"%s\"", serverAddress))

	clientCertData, err := os.ReadFile(clientCertificate)
	if err != nil {
		return "", err
	}
	kubeconfig = strings.ReplaceAll(kubeconfig, "$CLIENT_CERTIFICATE", base64.StdEncoding.EncodeToString(clientCertData))

	clientKeyData, err := os.ReadFile(clientKey)
	if err != nil {
		return "", err
	}
	kubeconfig = strings.ReplaceAll(kubeconfig, "$CLIENT_KEY", base64.StdEncoding.EncodeToString(clientKeyData))

	return kubeconfig, nil
}
