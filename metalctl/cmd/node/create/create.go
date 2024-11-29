package create

import (
	"errors"
	"fmt"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
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
var kubeAPIServerURL string
var kubeAPIServerHash string
var mtlsCertFilePath string
var mtlsKeyFilePath string

func Cmd() *cobra.Command {
	create := &cobra.Command{
		Use:   "create [id]",
		Short: "create a node on a federation and sign it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			signer, err := crypto.SignerFromFile(certFile, keyFile)
			if err != nil {
				return err
			}
			nodeGoalState := &config.NodeGoalState{
				ID:                            id,
				CreatedAt:                     time.Now().UTC(),
				WireguardMeshMember:           wireguardMeshMember,
				EtcdMember:                    etcdMember,
				KubernetesControlPlane:        kubernetesControlPlane,
				KubernetesWorker:              kubernetesWorker,
				KubernetesAPIServerBinary:     kubeAPIServerURL,
				KubernetesAPIServerBinaryHash: kubeAPIServerHash,
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
	create.PersistentFlags().StringVar(&kubeAPIServerURL, "kube-apiserver-url", "", "URL of kube-apiserver binary to download")
	create.PersistentFlags().StringVar(&kubeAPIServerHash, "kube-apiserver-hash", "", "Expected sha256 hash of kube-apiserver binary")
	create.PersistentFlags().StringVar(&mtlsCertFilePath, "mtls-cert-file-path", "", "Mutual TLS Certificate File Path")
	create.PersistentFlags().StringVar(&mtlsKeyFilePath, "mtls-key-file-path", "", "Mutual TLS Key File Path")
	return create
}
