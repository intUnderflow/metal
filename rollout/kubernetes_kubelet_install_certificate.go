package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
)

type kubernetesKubeletInstallCertificate struct {
	nodeID               string
	kubeletCertificate   string
	kubeProxyCertificate string
	kubeletService       kubelet.Kubelet
}

func (k *kubernetesKubeletInstallCertificate) NodeID() string {
	return k.nodeID
}

func (k *kubernetesKubeletInstallCertificate) Apply(_ context.Context) error {
	err := k.kubeletService.FulfillCertificate(k.kubeProxyCertificate, "proxy")
	if err != nil {
		return err
	}
	return k.kubeletService.FulfillCertificate(k.kubeletCertificate, "kubelet")
}

func (k *kubernetesKubeletInstallCertificate) Priority() Priority {
	return Priority{
		Major: 17,
		Minor: 0,
	}
}

func (k *kubernetesKubeletInstallCertificate) BasicDisplayTextForHumans() string {
	return fmt.Sprintf("Install a certificate")
}

func (k *kubernetesKubeletInstallCertificate) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Need to install certificate to node %s with content %s", k.nodeID, k.certificate)
}
