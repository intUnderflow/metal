package list

import (
	"errors"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/coredns"
	"github.com/intunderflow/metal/agent/go/actualstate/dns"
	"github.com/intunderflow/metal/agent/go/actualstate/etcd"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/apiserver"
	controller_manager "github.com/intunderflow/metal/agent/go/actualstate/kubernetes/controller-manager"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/proxy"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/scheduler"
	"github.com/intunderflow/metal/agent/go/actualstate/pki"
	"github.com/intunderflow/metal/agent/go/actualstate/wireguard"
	"github.com/intunderflow/metal/mtls"
	"github.com/intunderflow/metal/net"
	"github.com/intunderflow/metal/rollout"
	"github.com/spf13/cobra"
	"os"
)

var (
	wireguardKeyPath                            = os.Getenv("WIREGUARD_KEY_PATH")
	wireguardConfigFilePath                     = os.Getenv("WIREGUARD_CONFIG_FILE_PATH")
	wireguardSystemdName                        = os.Getenv("WIREGUARD_SYSTEMD_NAME")
	etcdConfigFilePath                          = os.Getenv("ETCD_CONFIG_FILE_PATH")
	etcdSystemdName                             = os.Getenv("ETCD_SYSTEMD_NAME")
	kubernetesApiServerPath                     = os.Getenv("KUBERNETES_API_SERVER_PATH")
	kubernetesApiServerLaunchScriptPath         = os.Getenv("KUBERNETES_API_SERVER_LAUNCH_SCRIPT_PATH")
	kubernetesApiServerSystemdName              = os.Getenv("KUBERNETES_API_SERVER_SYSTEMD_NAME")
	kubernetesServiceAccountSigningKeyFile      = os.Getenv("KUBERNETES_SERVICE_ACCOUNT_SIGNING_KEY_FILE")
	kubernetesServiceAccountKeyFile             = os.Getenv("KUBERNETES_SERVICE_ACCOUNT_KEY_FILE")
	kubernetesCAFile                            = os.Getenv("KUBERNETES_CA_FILE_PATH")
	kubernetesAPIServerCertFile                 = os.Getenv("KUBERNETES_API_SERVER_CERT_FILE")
	kubernetesAPIServerKeyFile                  = os.Getenv("KUBERNETES_API_SERVER_KEY_FILE")
	kubernetesEncryptionConfigFile              = os.Getenv("KUBERNETES_ENCRYPTION_CONFIG_FILE")
	kubernetesControllerManagerPath             = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_PATH")
	kubernetesControllerManagerLaunchScriptPath = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_LAUNCH_SCRIPT_PATH")
	kubernetesControllerManagerSystemdName      = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_SYSTEMD_NAME")
	kubernetesControllerManagerKubeConfigFile   = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_KUBECONFIG_FILE")
	kubernetesControllerManagerCertFile         = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_CERT_FILE")
	kubernetesControllerManagerKeyFile          = os.Getenv("KUBERNETES_CONTROLLER_MANAGER_KEY_FILE")
	kubernetesSchedulerPath                     = os.Getenv("KUBERNETES_SCHEDULER_PATH")
	kubernetesSchedulerLaunchScriptPath         = os.Getenv("KUBERNETES_SCHEDULER_LAUNCH_SCRIPT_PATH")
	kubernetesSchedulerSystemdName              = os.Getenv("KUBERNETES_SCHEDULER_SYSTEMD_NAME")
	kubernetesSchedulerKubeConfigFile           = os.Getenv("KUBERNETES_SCHEDULER_KUBECONFIG_FILE")
	kubernetesSchedulerCertFile                 = os.Getenv("KUBERNETES_SCHEDULER_CERT_FILE")
	kubernetesSchedulerKeyFile                  = os.Getenv("KUBERNETES_SCHEDULER_KEY_FILE")
	kubernetesKubeletPath                       = os.Getenv("KUBERNETES_KUBELET_PATH")
	kubernetesKubeletLaunchScriptPath           = os.Getenv("KUBERNETES_KUBELET_LAUNCH_SCRIPT_PATH")
	kubernetesKubeletSystemdName                = os.Getenv("KUBERNETES_KUBELET_SYSTEMD_NAME")
	kubernetesKubeletCAFile                     = os.Getenv("KUBERNETES_KUBELET_CA_FILE")
	kubernetesKubeletKubeConfigFile             = os.Getenv("KUBERNETES_KUBELET_KUBECONFIG_FILE")
	kubernetesKubeletKubeletConfigFile          = os.Getenv("KUBERNETES_KUBELET_KUBELET_CONFIG_FILE")
	kubernetesKubeletCertFile                   = os.Getenv("KUBERNETES_KUBELET_CERT_FILE")
	kubernetesKubeletKeyFile                    = os.Getenv("KUBERNETES_KUBELET_KEY_FILE")
	coreDNSPath                                 = os.Getenv("COREDNS_PATH")
	coreDNSLaunchScriptPath                     = os.Getenv("COREDNS_LAUNCH_SCRIPT_PATH")
	coreDNSSystemdName                          = os.Getenv("COREDNS_SYSTEMD_NAME")
	coreDNSCorefile                             = os.Getenv("COREDNS_COREFILE")
	coreDNSCertFile                             = os.Getenv("COREDNS_CERT_FILE")
	coreDNSKeyFile                              = os.Getenv("COREDNS_KEY_FILE")
	coreDNSKubeConfigFile                       = os.Getenv("COREDNS_KUBECONFIG_FILE")
	kubernetesProxyPath                         = os.Getenv("KUBERNETES_PROXY_PATH")
	kubernetesProxyLaunchScriptPath             = os.Getenv("KUBERNETES_PROXY_LAUNCH_SCRIPT_PATH")
	kubernetesProxySystemdName                  = os.Getenv("KUBERNETES_PROXY_SYSTEMD_NAME")
	kubernetesProxyConfigFile                   = os.Getenv("KUBERNETES_PROXY_CONFIG_FILE")
)

var broker string
var detailed bool
var mtlsCertFilePath string
var mtlsKeyFilePath string

func Cmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "list",
		Short: "List rollouts on a federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if broker == "" {
				return errors.New("broker is required")
			}

			client, err := mtls.GetClient(mtlsCertFilePath, mtlsKeyFilePath)
			if err != nil {
				return err
			}

			config, err := net.NewBroker(broker, client).GetConfig(cmd.Context())
			if err != nil {
				return err
			}

			pkiService, err := pki.NewPKI("/tmp/metalctlpki.pem", "")
			if err != nil {
				return err
			}

			kubernetesControllerManagerService := controller_manager.NewControllerManager(
				pkiService,
				"",
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
				"",
				kubernetesSchedulerPath,
				kubernetesSchedulerLaunchScriptPath,
				kubernetesCAFile,
				kubernetesSchedulerSystemdName,
				kubernetesSchedulerKubeConfigFile,
				kubernetesSchedulerCertFile,
				kubernetesSchedulerKeyFile,
			)

			kubeletService := kubelet.NewKubelet(
				"",
				kubernetesKubeletPath,
				kubernetesKubeletLaunchScriptPath,
				kubernetesKubeletSystemdName,
				kubernetesKubeletCAFile,
				kubernetesKubeletKubeConfigFile,
				kubernetesKubeletKubeletConfigFile,
				kubernetesKubeletCertFile,
				kubernetesKubeletKeyFile,
			)

			coreDNSService := coredns.NewCoreDNS(
				"",
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
			)

			rolloutService := rollout.NewService(
				wireguard.NewWireguard("", wireguardKeyPath, wireguardConfigFilePath, wireguardSystemdName),
				etcd.NewEtcd("", etcdConfigFilePath, etcdSystemdName),
				apiserver.NewApiServer(pkiService, "", kubernetesApiServerPath, kubernetesApiServerLaunchScriptPath, kubernetesApiServerSystemdName, kubernetesServiceAccountSigningKeyFile, kubernetesServiceAccountKeyFile, kubernetesCAFile, kubernetesAPIServerCertFile, kubernetesAPIServerKeyFile, kubernetesEncryptionConfigFile),
				kubernetesControllerManagerService,
				kubernetesSchedulerService,
				dns.NewDNS("/tmp/dns.metalctl"),
				pkiService,
				kubeletService,
				coreDNSService,
				kubeProxyService,
			)
			rollouts, err := rolloutService.GetRollouts(config)
			if err != nil {
				return err
			}
			fmt.Printf("-%d rollouts\n", len(rollouts))
			for i, currentRollout := range rollouts {
				fmt.Printf("#%d: node %s - %s\n", i+1, currentRollout.NodeID(), currentRollout.BasicDisplayTextForHumans())
				if detailed {
					fmt.Printf("%s\n", currentRollout.DetailedDisplayTextForHumans())
				}
			}
			return nil
		},
	}
	list.PersistentFlags().StringVar(&broker, "broker", "", "Broker server URL")
	list.PersistentFlags().BoolVar(&detailed, "detailed", false, "Show detailed rollout information")
	list.PersistentFlags().StringVar(&mtlsCertFilePath, "mtls-cert-file-path", "", "Mutual TLS Certificate File Path")
	list.PersistentFlags().StringVar(&mtlsKeyFilePath, "mtls-key-file-path", "", "Mutual TLS Key File Path")
	return list
}
