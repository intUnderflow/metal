package coredns

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

//go:embed Corefile
var _corefile string

//go:embed kubeconfig.yaml
var _kubeconfig string

type CoreDNS interface {
	GetCurrentlyAppliedSpec() *config.CoreDNSSpec
	ApplySpec(spec *config.CoreDNSSpec) error
	CheckHealthy(context.Context) error
	RestartService(context.Context) error
}

func NewCoreDNS(
	nodeID string,
	coreDNSPath string,
	launchScriptPath string,
	serviceSystemdName string,
	caFile string,
	coreDNSCertFile string,
	coreDNSKeyFile string,
	coreDNSKubeConfigFile string,
	coreDNSCorefile string,
	pkiService pki.PKI,
) CoreDNS {
	return &coreDNSImpl{
		mutex:                 &sync.RWMutex{},
		nodeID:                nodeID,
		coreDNSPath:           coreDNSPath,
		launchScriptPath:      launchScriptPath,
		serviceSystemdName:    serviceSystemdName,
		caFile:                caFile,
		coreDNSCertFile:       coreDNSCertFile,
		coreDNSKeyFile:        coreDNSKeyFile,
		coreDNSKubeconfigFile: coreDNSKubeConfigFile,
		coreDNSCorefile:       coreDNSCorefile,
		pkiService:            pkiService,
		currentlyAppliedSpec:  nil,
		sequenceNumber:        0,
		lastRestart:           time.Unix(0, 0),
	}
}

type coreDNSImpl struct {
	mutex                 *sync.RWMutex
	nodeID                string
	coreDNSPath           string
	launchScriptPath      string
	serviceSystemdName    string
	caFile                string
	coreDNSCertFile       string
	coreDNSKeyFile        string
	coreDNSKubeconfigFile string
	coreDNSCorefile       string
	pkiService            pki.PKI
	currentlyAppliedSpec  *config.CoreDNSSpec
	sequenceNumber        int
	lastRestart           time.Time
}

func (c *coreDNSImpl) GetCurrentlyAppliedSpec() *config.CoreDNSSpec {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.currentlyAppliedSpec
}

func (c *coreDNSImpl) ApplySpec(spec *config.CoreDNSSpec) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	err := c.ensureCrypto()
	if err != nil {
		return err
	}

	c.sequenceNumber = c.sequenceNumber + 1

	err = os.WriteFile(c.coreDNSCorefile, []byte(_corefile), 0600)
	if err != nil {
		return err
	}

	kubeconfigPath := fmt.Sprintf("%s.%d", c.coreDNSKubeconfigFile, c.sequenceNumber)

	kubeconfig, err := toKubeconfig(c.caFile, spec.Endpoint, c.coreDNSCertFile, c.coreDNSKeyFile)
	if err != nil {
		return err
	}

	err = os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0600)
	if err != nil {
		return err
	}

	launchScript := toCoreDNSLaunchScript(c.coreDNSPath, spec, c.caFile, c.coreDNSCertFile, c.coreDNSKeyFile, kubeconfigPath, c.coreDNSCorefile)

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

func (c *coreDNSImpl) CheckHealthy(ctx context.Context) error {
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

func (c *coreDNSImpl) RestartService(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	c.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", c.serviceSystemdName).Run()
}

func (c *coreDNSImpl) ensureCrypto() error {
	var certificate []byte
	var err error
	if _, err = os.ReadFile(c.coreDNSCertFile); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		marshalledKey, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		certificate, err = c.pkiService.IssueSuperAdminCertificate(c.nodeID, &key.PublicKey)
		if err != nil {
			return err
		}

		err = os.WriteFile(c.coreDNSCertFile, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate,
		}), 0600)
		if err != nil {
			return err
		}
		err = os.WriteFile(c.coreDNSKeyFile, pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: marshalledKey,
		}), 0600)
		if err != nil {
			return err
		}
	}

	return nil
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

func toCoreDNSLaunchScript(coreDNSPath string, spec *config.CoreDNSSpec, caFile string, certFile string, keyFile string, kubeConfig string, coreFile string) string {
	args := map[string]string{}

	args["PORT"] = strconv.Itoa(spec.Port)
	args["K8S_ENDPOINT"] = spec.Endpoint
	args["TLS_CERT"] = certFile
	args["TLS_KEY"] = keyFile
	args["TLS_CA"] = caFile
	args["KUBECONFIG"] = kubeConfig

	var argStrings []string
	for key, value := range args {
		argStrings = append(argStrings, fmt.Sprintf("%s=%s", key, value))
	}

	return fmt.Sprintf("%s %s -conf %s", strings.Join(argStrings, " "), coreDNSPath, coreFile)
}
