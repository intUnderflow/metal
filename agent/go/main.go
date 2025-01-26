package main

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate"
	"github.com/intunderflow/metal/agent/go/actualstate/coredns"
	"github.com/intunderflow/metal/agent/go/actualstate/customrollouts"
	"github.com/intunderflow/metal/agent/go/actualstate/dns"
	"github.com/intunderflow/metal/agent/go/actualstate/downloader"
	"github.com/intunderflow/metal/agent/go/actualstate/endpoint"
	"github.com/intunderflow/metal/agent/go/actualstate/etcd"
	"github.com/intunderflow/metal/agent/go/actualstate/extradata"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/apiserver"
	controller_manager "github.com/intunderflow/metal/agent/go/actualstate/kubernetes/controller-manager"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/proxy"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/scheduler"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
	"github.com/intunderflow/metal/agent/go/actualstate/wireguard"
	"github.com/intunderflow/metal/agent/go/handshake"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"github.com/intunderflow/metal/mtls"
	"github.com/intunderflow/metal/net"
	"github.com/intunderflow/metal/rollout"
	"github.com/intunderflow/metal/wrapper"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	maximumReconcileWaitTime = os.Getenv("MAXIMUM_RECONCILE_WAIT_TIME")
	nodeID                   = os.Getenv("NODE_ID")
	broker                   = os.Getenv("BROKER")
	rootCAPath               = os.Getenv("ROOT_CA_PATH")
	certFilePath             = os.Getenv("CERT_FILE_PATH")
	keyFilePath              = os.Getenv("KEY_FILE_PATH")
	wireguardKeyPath         = os.Getenv("WIREGUARD_KEY_PATH")
	wireguardConfigFilePath  = os.Getenv("WIREGUARD_CONFIG_FILE_PATH")
	wireguardSystemdName     = os.Getenv("WIREGUARD_SYSTEMD_NAME")
	etcdConfigFilePath       = os.Getenv("ETCD_CONFIG_FILE_PATH")
	etcdSystemdName          = os.Getenv("ETCD_SYSTEMD_NAME")
	hostsFilePath            = os.Getenv("HOSTS_FILE_PATH")

	kubernetesApiServerPath                = os.Getenv("KUBERNETES_API_SERVER_PATH")
	kubernetesApiServerLaunchScriptPath    = os.Getenv("KUBERNETES_API_SERVER_LAUNCH_SCRIPT_PATH")
	kubernetesApiServerSystemdName         = os.Getenv("KUBERNETES_API_SERVER_SYSTEMD_NAME")
	kubernetesServiceAccountSigningKeyFile = os.Getenv("KUBERNETES_SERVICE_ACCOUNT_SIGNING_KEY_FILE")
	kubernetesServiceAccountKeyFile        = os.Getenv("KUBERNETES_SERVICE_ACCOUNT_KEY_FILE")
	kubernetesEncryptionConfigFile         = os.Getenv("KUBERNETES_ENCRYPTION_CONFIG_FILE")
	// Used to store the nodes unique API server cert
	kubernetesAPIServerCertFile = os.Getenv("KUBERNETES_API_SERVER_CERT_FILE")
	// Used to store the nodes unique API server key
	kubernetesAPIServerKeyFile = os.Getenv("KUBERNETES_API_SERVER_KEY_FILE")

	kubernetesControllerManagerPath             = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_PATH")
	kubernetesControllerManagerLaunchScriptPath = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_LAUNCH_SCRIPT_PATH")
	kubernetesControllerManagerSystemdName      = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_SYSTEMD_NAME")
	kubernetesControllerManagerKubeConfigFile   = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_KUBECONFIG_FILE")
	kubernetesControllerManagerCertFile         = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_CERT_FILE")
	kubernetesControllerManagerKeyFile          = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_KEY_FILE")

	kubernetesSchedulerPath             = os.Getenv("KUBERNETES_SCHEDULER_PATH")
	kubernetesSchedulerLaunchScriptPath = os.Getenv("KUBERNETES_SCHEDULER_LAUNCH_SCRIPT_PATH")
	kubernetesSchedulerSystemdName      = os.Getenv("KUBERNETES_SCHEDULER_SYSTEMD_NAME")
	kubernetesSchedulerKubeConfigFile   = os.Getenv("KUBERNETES_SCHEDULER_KUBECONFIG_FILE")
	kubernetesSchedulerCertFile         = os.Getenv("KUBERNETES_SCHEDULER_CERT_FILE")
	kubernetesSchedulerKeyFile          = os.Getenv("KUBERNETES_SCHEDULER_KEY_FILE")

	kubernetesKubeletPath              = os.Getenv("KUBERNETES_KUBELET_PATH")
	kubernetesKubeletLaunchScriptPath  = os.Getenv("KUBERNETES_KUBELET_LAUNCH_SCRIPT_PATH")
	kubernetesKubeletSystemdName       = os.Getenv("KUBERNETES_KUBELET_SYSTEMD_NAME")
	kubernetesKubeletCAFile            = os.Getenv("KUBERNETES_KUBELET_CA_FILE")
	kubernetesKubeletKubeConfigFile    = os.Getenv("KUBERNETES_KUBELET_KUBECONFIG_FILE")
	kubernetesKubeletKubeletConfigFile = os.Getenv("KUBERNETES_KUBELET_KUBELET_CONFIG_FILE")
	kubernetesKubeletCertFile          = os.Getenv("KUBERNETES_KUBELET_CERT_FILE")
	kubernetesKubeletKeyFile           = os.Getenv("KUBERNETES_KUBELET_KEY_FILE")

	coreDNSPath             = os.Getenv("COREDNS_PATH")
	coreDNSLaunchScriptPath = os.Getenv("COREDNS_LAUNCH_SCRIPT_PATH")
	coreDNSSystemdName      = os.Getenv("COREDNS_SYSTEMD_NAME")
	coreDNSCorefile         = os.Getenv("COREDNS_COREFILE")
	coreDNSCertFile         = os.Getenv("COREDNS_CERT_FILE")
	coreDNSKeyFile          = os.Getenv("COREDNS_KEY_FILE")
	coreDNSKubeConfigFile   = os.Getenv("COREDNS_KUBECONFIG_FILE")

	kubernetesProxyPath             = os.Getenv("KUBERNETES_PROXY_PATH")
	kubernetesProxyLaunchScriptPath = os.Getenv("KUBERNETES_PROXY_LAUNCH_SCRIPT_PATH")
	kubernetesProxySystemdName      = os.Getenv("KUBERNETES_PROXY_SYSTEMD_NAME")
	kubernetesProxyConfigFile       = os.Getenv("KUBERNETES_PROXY_CONFIG_FILE")
	kubernetesProxyCertFile         = os.Getenv("KUBERNETES_PROXY_CERT_FILE")
	kubernetesProxyKubeConfigFile   = os.Getenv("KUBERNETES_PROXY_KUBECONFIG_FILE")

	downloaderFilePath = os.Getenv("DOWNLOADER_FILE_PATH")

	extraDataFilePath = os.Getenv("EXTRA_DATA_FILE_PATH")

	// Used to store the CA bundle for Kubernetes from all nodes
	kubernetesCAFile = os.Getenv("KUBERNETES_CA_FILE_PATH")
	// Used to store the nodes unique CA
	pkiCAPath = os.Getenv("PKI_CA_PATH")
)

func main() {
	err := run()
	if err != nil {
		panic(err)
	}
}

func run() error {
	maximumReconcileWaitTimeInt, err := strconv.Atoi(maximumReconcileWaitTime)
	if err != nil {
		fmt.Printf("warning: maximumReconcileWaitTimeInt invalid or not supplied (value \"%s\") - using default\n", maximumReconcileWaitTime)
		maximumReconcileWaitTimeInt = 15
	}

	wrap := wrapper.NewWrapper(config.NewConfig())
	verifier, err := crypto.PKIVerifierFromFile(rootCAPath)
	if err != nil {
		return err
	}
	client, err := mtls.GetClient(certFilePath, keyFilePath)
	if err != nil {
		return err
	}
	netBroker := net.NewBroker(broker, client)
	signer, err := crypto.SignerFromFile(certFilePath, keyFilePath)
	if err != nil {
		return err
	}
	pkiService, err := pki.NewPKI(pkiCAPath, nodeID+".node.metal.local")
	if err != nil {
		return err
	}
	endpointGetter := endpoint.NewEndpoint(client, broker)
	wireguardService := wireguard.NewWireguard(nodeID, wireguardKeyPath, wireguardConfigFilePath, wireguardSystemdName)
	etcdService := etcd.NewEtcd(nodeID, etcdConfigFilePath, etcdSystemdName)
	kubernetesApiServerService := apiserver.NewApiServer(
		pkiService,
		nodeID,
		kubernetesApiServerPath,
		kubernetesApiServerLaunchScriptPath,
		kubernetesApiServerSystemdName,
		kubernetesServiceAccountSigningKeyFile,
		kubernetesServiceAccountKeyFile,
		kubernetesCAFile,
		kubernetesAPIServerCertFile,
		kubernetesAPIServerKeyFile,
		kubernetesEncryptionConfigFile,
	)
	kubernetesControllerManagerService := controller_manager.NewControllerManager(
		pkiService,
		nodeID,
		kubernetesControllerManagerPath,
		kubernetesControllerManagerLaunchScriptPath,
		kubernetesCAFile,
		kubernetesControllerManagerSystemdName,
		kubernetesControllerManagerKubeConfigFile,
		kubernetesControllerManagerCertFile,
		kubernetesControllerManagerKeyFile,
	)
	kubernetesSchedulerService := scheduler.NewScheduler(
		pkiService,
		nodeID,
		kubernetesSchedulerPath,
		kubernetesSchedulerLaunchScriptPath,
		kubernetesCAFile,
		kubernetesSchedulerSystemdName,
		kubernetesSchedulerKubeConfigFile,
		kubernetesSchedulerCertFile,
		kubernetesSchedulerKeyFile,
	)
	dnsService := dns.NewDNS(hostsFilePath)

	kubeletService := kubelet.NewKubelet(
		nodeID,
		kubernetesKubeletPath,
		kubernetesKubeletLaunchScriptPath,
		kubernetesKubeletSystemdName,
		kubernetesKubeletCAFile,
		kubernetesKubeletKubeConfigFile,
		kubernetesKubeletKubeletConfigFile,
		kubernetesKubeletCertFile,
		kubernetesKubeletKeyFile,
		kubernetesProxyCertFile,
	)
	coreDNSService := coredns.NewCoreDNS(
		nodeID,
		coreDNSPath,
		coreDNSLaunchScriptPath,
		coreDNSSystemdName,
		kubernetesCAFile,
		coreDNSCertFile,
		coreDNSKeyFile,
		coreDNSKubeConfigFile,
		coreDNSCorefile,
		pkiService,
	)
	kubeProxyService := proxy.NewProxy(
		kubernetesProxyPath,
		kubernetesProxyLaunchScriptPath,
		kubernetesProxySystemdName,
		kubernetesProxyConfigFile,
		kubernetesProxyKubeConfigFile,
		kubernetesProxyCertFile,
		kubernetesKubeletKeyFile,
		kubernetesCAFile,
	)
	downloadService := downloader.NewDownloader(downloaderFilePath)
	extraDataService := extradata.NewExtraData(extraDataFilePath)
	customRolloutsService := customrollouts.NewCustomRollouts()
	actualState := actualstate.NewActualState(nodeID, endpointGetter, wireguardService, etcdService, kubernetesApiServerService, kubernetesControllerManagerService, kubernetesSchedulerService, dnsService, pkiService, kubeletService, coreDNSService, kubeProxyService, downloadService, extraDataService, customRolloutsService)
	rolloutService := rollout.NewService(wireguardService, etcdService, kubernetesApiServerService, kubernetesControllerManagerService, kubernetesSchedulerService, dnsService, pkiService, kubeletService, coreDNSService, kubeProxyService, downloadService, extraDataService, customRolloutsService)

	requestTerminate := &atomic.Bool{}
	terminateChannel := make(chan os.Signal, 1)
	signal.Notify(terminateChannel, os.Interrupt)
	go func() {
		<-terminateChannel
		requestTerminate.Store(true)
	}()
	i := 0
	for !requestTerminate.Load() {
		i = i + 1
		err = runPeriodic(context.Background(), wrap, netBroker, signer, verifier, actualState, rolloutService, i)
		if err != nil {
			fmt.Printf("error executing periodic agent loop: %v\n", err)
		}
		actualState.SetReconciliationStatus(err)
		time.Sleep(time.Duration(1+rand.Intn(maximumReconcileWaitTimeInt)) * time.Second)
	}
	return nil
}

func runPeriodic(ctx context.Context, wrap *wrapper.ConfigWrapper, broker net.Broker, signer crypto.Signer, verifier crypto.Verifier, actualState actualstate.ActualState, rolloutService *rollout.Service, i int) error {
	wrap.Mutex.Lock()
	defer wrap.Mutex.Unlock()

	fmt.Printf("reconciling (run=%d)...\n", i)

	currentHandshake := handshake.NewHandshake(broker, verifier)
	err := currentHandshake.PullAndPush(ctx, wrap.Config)
	if err != nil {
		return err
	}

	newActualState, err := actualState.GetActualState(ctx)
	if err != nil {
		return err
	}
	actualStateSignature, err := signer.Sign(newActualState)
	if err != nil {
		return err
	}

	if wrap.Config.Nodes[newActualState.ID] != nil {
		wrap.Config.Nodes[newActualState.ID].ActualState = newActualState
		wrap.Config.Nodes[newActualState.ID].ActualStateSignature = actualStateSignature
		if wrap.Config.Nodes[newActualState.ID].GoalState != nil {
			actualState.InformGoalState(wrap.Config.Nodes[newActualState.ID].GoalState)
		}
	} else {
		fmt.Printf("warning: not publishing ActualState for node because node has no GoalState, id %s\n", newActualState.ID)
	}

	currentRollouts, err := rolloutService.GetRollouts(wrap.Config)
	if err != nil {
		return fmt.Errorf("error fetching rollouts: %v", err)
	}
	if len(currentRollouts) > 0 {
		nextRollout := currentRollouts[0]
		if nextRollout.NodeID() == nodeID {
			// Execute the rollout
			fmt.Printf("Executing the rollout %s\n", nextRollout.BasicDisplayTextForHumans())
			err = nextRollout.Apply(ctx)
			if err != nil {
				return err
			} else {
				fmt.Printf("Done with no errors.\n")
			}
		}
	}

	return nil
}
