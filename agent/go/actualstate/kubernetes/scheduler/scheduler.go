package scheduler

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

type Scheduler interface {
	GetCurrentlyAppliedSpec() *config.KubernetesSchedulerSpec
	ApplySpec(spec *config.KubernetesSchedulerSpec) error
	CheckHealthy(context.Context) error
	RestartService(context.Context) error
}

type schedulerImpl struct {
	mutex                   *sync.RWMutex
	pkiService              pki.PKI
	nodeID                  string
	schedulerPath           string
	launchScriptPath        string
	serviceSystemdName      string
	caFile                  string
	schedulerKubeConfigFile string
	schedulerCertFile       string
	schedulerKeyFile        string
	currentlyAppliedSpec    *config.KubernetesSchedulerSpec
	lastRestart             time.Time
	sequenceNumber          int
}

func NewScheduler(
	pkiService pki.PKI,
	nodeID string,
	schedulerPath string,
	launchScriptPath string,
	caFile string,
	serviceSystemdName string,
	schedulerKubeConfigFile string,
	schedulerCertFile string,
	schedulerKeyFile string,
) Scheduler {
	return &schedulerImpl{
		mutex:                   &sync.RWMutex{},
		pkiService:              pkiService,
		nodeID:                  nodeID,
		schedulerPath:           schedulerPath,
		launchScriptPath:        launchScriptPath,
		caFile:                  caFile,
		serviceSystemdName:      serviceSystemdName,
		schedulerKubeConfigFile: schedulerKubeConfigFile,
		schedulerCertFile:       schedulerCertFile,
		schedulerKeyFile:        schedulerKeyFile,
		currentlyAppliedSpec:    nil,
		lastRestart:             time.Unix(0, 0),
	}
}

func (s *schedulerImpl) GetCurrentlyAppliedSpec() *config.KubernetesSchedulerSpec {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.currentlyAppliedSpec
}

func (s *schedulerImpl) ApplySpec(spec *config.KubernetesSchedulerSpec) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.ensureCrypto()
	if err != nil {
		return err
	}

	s.sequenceNumber = s.sequenceNumber + 1

	launchScript, err := toSchedulerLaunchScript(
		s.schedulerPath,
		spec,
		s.caFile,
		s.schedulerKubeConfigFile,
		s.schedulerCertFile,
		s.schedulerKeyFile,
		s.sequenceNumber,
	)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.launchScriptPath, []byte(launchScript), 0600)
	if err != nil {
		return err
	}
	s.currentlyAppliedSpec = spec

	if s.sequenceNumber > 5 {
		s.sequenceNumber = 0
	}

	return nil
}

func (s *schedulerImpl) CheckHealthy(ctx context.Context) error {
	command := exec.CommandContext(ctx, "systemctl", "status", s.serviceSystemdName, "--no-pager")
	output, err := command.CombinedOutput()
	if err != nil {
		return err
	}
	if strings.Contains(string(output), "active (running)") || strings.Contains(string(output), "status=0/SUCCESS") {
		return nil
	}
	return errors.New(string(output))
}

func (s *schedulerImpl) RestartService(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	s.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", s.serviceSystemdName).Run()
}

func (s *schedulerImpl) ensureCrypto() error {
	var certificate []byte
	var err error
	if _, err = os.ReadFile(s.schedulerCertFile); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		marshalledKey, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		certificate, err = s.pkiService.IssueKubeSchedulerCertificate(s.nodeID, &key.PublicKey)
		if err != nil {
			return err
		}

		err = os.WriteFile(s.schedulerCertFile, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate,
		}), 0600)
		if err != nil {
			return err
		}
		err = os.WriteFile(s.schedulerKeyFile, pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: marshalledKey,
		}), 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func toSchedulerLaunchScript(
	binaryPath string,
	spec *config.KubernetesSchedulerSpec,
	caFile string,
	schedulerKubeConfigFile string,
	schedulerCertFile string,
	schedulerKeyFile string,
	sequenceNumber int,
) (string, error) {
	kubeconfigContents, err := toKubeconfig(caFile, spec.ServerAddress, schedulerCertFile, schedulerKeyFile)
	if err != nil {
		return "", err
	}

	kubeconfigPath := schedulerKubeConfigFile + "." + strconv.Itoa(sequenceNumber)
	err = os.WriteFile(kubeconfigPath, []byte(kubeconfigContents), 0600)
	if err != nil {
		return "", err
	}

	args := map[string]string{}
	args["bind-address"] = spec.AdvertiseAddress
	args["secure-port"] = strconv.Itoa(spec.SecurePort)
	args["kubeconfig"] = kubeconfigPath
	args["authentication-kubeconfig"] = kubeconfigPath
	args["authorization-kubeconfig"] = kubeconfigPath

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
