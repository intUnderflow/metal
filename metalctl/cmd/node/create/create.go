package create

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"github.com/intunderflow/metal/metalctl/lib/manifest"
	"github.com/intunderflow/metal/mtls"
	"github.com/intunderflow/metal/net"
	"github.com/spf13/cobra"
	"time"
)

var broker string
var certFile string
var keyFile string
var wireguardMeshMember bool
var etcdMember bool
var kubernetesControlPlane bool
var kubernetesWorker bool
var etcdURL string
var etcdHash string
var kubeAPIServerURL string
var kubeAPIServerHash string
var kubeControllerManagerURL string
var kubeControllerManagerHash string
var kubeSchedulerURL string
var kubeSchedulerHash string
var kubeletURL string
var kubeletHash string
var kubeProxyURL string
var kubeProxyHash string
var coreDNSURL string
var coreDNSHash string
var manifestPath string
var mtlsCertFilePath string
var mtlsKeyFilePath string
var customRollouts string

func Cmd() *cobra.Command {
	create := &cobra.Command{
		Use:   "create [id]",
		Short: "create a node on a federation and sign it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			id := args[0]
			if id == "" {
				return errors.New("Node ID (first argument) is required")
			}
			if broker == "" {
				return errors.New("broker is required")
			}
			if certFile == "" {
				return errors.New("cert-file is required")
			}
			if keyFile == "" {
				return errors.New("key-file is required")
			}
			manifestContent := &manifest.Manifest{}
			if manifestPath != "" {
				manifestContent, err = manifest.FromFile(manifestPath)
				if err != nil {
					return err
				}
			}
			if etcdURL != "" {
				manifestContent.Etcd.URL = etcdURL
			}
			if etcdHash != "" {
				manifestContent.Etcd.Hash = etcdHash
			}
			if kubeAPIServerURL != "" {
				manifestContent.KubeAPIServer.URL = kubeAPIServerURL
			}
			if kubeAPIServerHash != "" {
				manifestContent.KubeAPIServer.Hash = kubeAPIServerHash
			}
			if kubeControllerManagerURL != "" {
				manifestContent.KubeControllerManager.URL = kubeControllerManagerURL
			}
			if kubeControllerManagerHash != "" {
				manifestContent.KubeControllerManager.Hash = kubeControllerManagerHash
			}
			if kubeSchedulerURL != "" {
				manifestContent.KubeScheduler.URL = kubeSchedulerURL
			}
			if kubeSchedulerHash != "" {
				manifestContent.KubeScheduler.Hash = kubeSchedulerHash
			}
			if kubeletURL != "" {
				manifestContent.Kubelet.URL = kubeletURL
			}
			if kubeletHash != "" {
				manifestContent.Kubelet.Hash = kubeletHash
			}
			if kubeProxyURL != "" {
				manifestContent.KubeProxy.URL = kubeProxyURL
			}
			if kubeProxyHash != "" {
				manifestContent.KubeProxy.Hash = kubeProxyHash
			}
			if coreDNSURL != "" {
				manifestContent.CoreDNS.URL = coreDNSURL
			}
			if coreDNSHash != "" {
				manifestContent.CoreDNS.Hash = coreDNSHash
			}
			customRolloutsMap := map[string]config.CustomRolloutSpec{}
			if customRollouts != "" {
				customRolloutsMap, err = unmarshalCustomRollouts(customRollouts)
				if err != nil {
					return err
				}
			}
			signer, err := crypto.SignerFromFile(certFile, keyFile)
			if err != nil {
				return err
			}
			nodeGoalState := &config.NodeGoalState{
				ID:                                    id,
				CreatedAt:                             time.Now().UTC(),
				WireguardMeshMember:                   wireguardMeshMember,
				EtcdMember:                            etcdMember,
				KubernetesControlPlane:                kubernetesControlPlane,
				KubernetesWorker:                      kubernetesWorker,
				EtcdBinary:                            manifestContent.Etcd.URL,
				EtcdBinaryHash:                        manifestContent.Etcd.Hash,
				KubernetesAPIServerBinary:             manifestContent.KubeAPIServer.URL,
				KubernetesAPIServerBinaryHash:         manifestContent.KubeAPIServer.Hash,
				KubernetesControllerManagerBinary:     manifestContent.KubeControllerManager.URL,
				KubernetesControllerManagerBinaryHash: manifestContent.KubeControllerManager.Hash,
				KubernetesSchedulerBinary:             manifestContent.KubeScheduler.URL,
				KubernetesSchedulerBinaryHash:         manifestContent.KubeScheduler.Hash,
				KubernetesKubeletBinary:               manifestContent.Kubelet.URL,
				KubernetesKubeletBinaryHash:           manifestContent.Kubelet.Hash,
				KubernetesProxyBinary:                 manifestContent.KubeProxy.URL,
				KubernetesProxyBinaryHash:             manifestContent.KubeProxy.Hash,
				CoreDNSBinary:                         manifestContent.CoreDNS.URL,
				CoreDNSBinaryHash:                     manifestContent.CoreDNS.Hash,
				CustomRolloutSpec:                     customRolloutsMap,
			}
			signature, err := signer.Sign(nodeGoalState)
			if err != nil {
				return err
			}

			client, err := mtls.GetClient(mtlsCertFilePath, mtlsKeyFilePath)
			if err != nil {
				return err
			}

			err = net.NewBroker(broker, client).SetNodeGoalState(cmd.Context(), nodeGoalState, signature)
			if err != nil {
				return err
			}

			fmt.Println("Wrote the goal state to the broker")
			return nil
		},
	}
	create.PersistentFlags().StringVar(&broker, "broker", "", "Broker server URL")
	create.PersistentFlags().StringVar(&certFile, "cert-file", "", "Certificate file")
	create.PersistentFlags().StringVar(&keyFile, "key-file", "", "Key file")
	create.PersistentFlags().BoolVar(&wireguardMeshMember, "wireguard-mesh-member", false, "Give node wireguard membership")
	create.PersistentFlags().BoolVar(&etcdMember, "etcd-member", false, "Give node etcd membership")
	create.PersistentFlags().BoolVar(&kubernetesControlPlane, "kubernetes-control-plane", false, "Give node kubernetes control plane membership")
	create.PersistentFlags().BoolVar(&kubernetesWorker, "kubernetes-worker", false, "Give node kubernetes worker status")
	create.PersistentFlags().StringVar(&etcdURL, "etcd-url", "", "Etcd server URL")
	create.PersistentFlags().StringVar(&etcdHash, "etcd-hash", "", "Etcd server hash")
	create.PersistentFlags().StringVar(&kubeAPIServerURL, "kube-apiserver-url", "", "URL of kube-apiserver binary to download")
	create.PersistentFlags().StringVar(&kubeAPIServerHash, "kube-apiserver-hash", "", "Expected sha256 hash of kube-apiserver binary")
	create.PersistentFlags().StringVar(&kubeControllerManagerURL, "kube-controller-manager-url", "", "URL of kube-controller-manager binary")
	create.PersistentFlags().StringVar(&kubeControllerManagerHash, "kube-controller-manager-hash", "", "Expected sha256 hash of kube-controller-manager binary")
	create.PersistentFlags().StringVar(&kubeSchedulerURL, "kube-scheduler-url", "", "URL of kube-scheduler binary")
	create.PersistentFlags().StringVar(&kubeSchedulerHash, "kube-scheduler-hash", "", "Expected sha256 hash of kube-scheduler binary")
	create.PersistentFlags().StringVar(&kubeletURL, "kubelet-url", "", "URL of kubelet binary")
	create.PersistentFlags().StringVar(&kubeletHash, "kubelet-hash", "", "Expected sha256 hash of kubelet binary")
	create.PersistentFlags().StringVar(&kubeProxyURL, "kube-proxy-url", "", "URL of kube-proxy binary")
	create.PersistentFlags().StringVar(&kubeProxyHash, "kube-proxy-hash", "", "Expected sha256 hash of kube-proxy binary")
	create.PersistentFlags().StringVar(&coreDNSURL, "core-dns-url", "", "URL of CoreDNS binary")
	create.PersistentFlags().StringVar(&coreDNSHash, "core-dns-hash", "", "Expected sha256 hash of CoreDNS binary")
	create.PersistentFlags().StringVar(&customRollouts, "custom-rollouts", "", "Custom rollouts")
	create.PersistentFlags().StringVar(&manifestPath, "manifest-path", "", "Path to manifest of Kubernetes binaries and hashes")
	create.PersistentFlags().StringVar(&mtlsCertFilePath, "mtls-cert-file-path", "", "Mutual TLS Certificate File Path")
	create.PersistentFlags().StringVar(&mtlsKeyFilePath, "mtls-key-file-path", "", "Mutual TLS Key File Path")
	return create
}

func unmarshalCustomRollouts(input string) (map[string]config.CustomRolloutSpec, error) {
	var result map[string]config.CustomRolloutSpec
	err := json.Unmarshal([]byte(input), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
