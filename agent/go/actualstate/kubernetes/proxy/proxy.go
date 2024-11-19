package proxy

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/config"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	//go:embed kube-proxy.yaml
	_kubeProxyConfig string
)

type Proxy interface {
	GetCurrentlyAppliedSpec() *config.KubernetesProxySpec
	ApplySpec(spec *config.KubernetesProxySpec) error
	CheckHealthy(context.Context) error
	RestartService(context.Context) error
}

type proxyImpl struct {
	mutex                *sync.RWMutex
	proxyPath            string
	launchScriptPath     string
	serviceSystemdName   string
	proxyConfigFile      string
	currentlyAppliedSpec *config.KubernetesProxySpec
	lastRestart          time.Time
	sequenceNumber       int
}

func NewProxy(
	proxyPath string,
	launchScriptPath string,
	serviceSystemdName string,
	proxyConfigFile string,
) Proxy {
	return &proxyImpl{
		mutex:                &sync.RWMutex{},
		proxyPath:            proxyPath,
		launchScriptPath:     launchScriptPath,
		serviceSystemdName:   serviceSystemdName,
		proxyConfigFile:      proxyConfigFile,
		currentlyAppliedSpec: nil,
		lastRestart:          time.Unix(0, 0),
		sequenceNumber:       0,
	}
}

func (p *proxyImpl) GetCurrentlyAppliedSpec() *config.KubernetesProxySpec {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.currentlyAppliedSpec
}

func (p *proxyImpl) ApplySpec(spec *config.KubernetesProxySpec) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.sequenceNumber = p.sequenceNumber + 1

	configFilePath := fmt.Sprintf("%s.%d", p.proxyConfigFile, p.sequenceNumber)
	configFile := generateKubeProxyConfig(spec.KubeconfigPath, spec.ClusterCIDR)

	err := os.WriteFile(configFilePath, []byte(configFile), 0600)
	if err != nil {
		return err
	}

	launchScript := toLaunchScript(p.proxyPath, configFilePath)

	err = os.WriteFile(p.launchScriptPath, []byte(launchScript), 0600)
	if err != nil {
		return err
	}

	p.currentlyAppliedSpec = spec

	if p.sequenceNumber > 5 {
		p.sequenceNumber = 0
	}
	return nil
}

func (p *proxyImpl) CheckHealthy(ctx context.Context) error {
	command := exec.CommandContext(ctx, "systemctl", "status", p.serviceSystemdName, "--no-pager")
	output, err := command.CombinedOutput()
	if err != nil {
		return err
	}
	if strings.Contains(string(output), "active (running)") || strings.Contains(string(output), "status=0/SUCCESS") {
		return nil
	}
	return errors.New(string(output))
}

func (p *proxyImpl) RestartService(ctx context.Context) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.lastRestart.Add(time.Minute).After(time.Now()) {
		// Don't try restarting if it's been less than a minute
		return nil
	}
	p.lastRestart = time.Now()

	return exec.CommandContext(ctx, "systemctl", "restart", p.serviceSystemdName).Run()
}

func generateKubeProxyConfig(kubeConfigPath string, clusterCIDR string) string {
	kubeproxyConfig := _kubeProxyConfig

	kubeproxyConfig = strings.ReplaceAll(kubeproxyConfig, "$KUBECONFIG_PATH", fmt.Sprintf("\"%s\"", kubeConfigPath))

	kubeproxyConfig = strings.ReplaceAll(kubeproxyConfig, "$CLUSTER_CIDR", fmt.Sprintf("\"%s\"", clusterCIDR))

	return kubeproxyConfig
}

func toLaunchScript(kubeProxyPath string, configPath string) string {
	return fmt.Sprintf("%s --config=%s", kubeProxyPath, configPath)
}
