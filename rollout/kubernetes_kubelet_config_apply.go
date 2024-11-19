package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
	"github.com/intunderflow/metal/config"
)

type kubernetesKubeletConfigApply struct {
	nodeID         string
	specToApply    *config.KubernetesKubeletSpec
	kubeletService kubelet.Kubelet
}

func (e *kubernetesKubeletConfigApply) NodeID() string {
	return e.nodeID
}

func (e *kubernetesKubeletConfigApply) Apply(_ context.Context) error {
	return e.kubeletService.ApplySpec(e.specToApply)
}

func (e *kubernetesKubeletConfigApply) Priority() Priority {
	return Priority{
		Major: 18,
		Minor: 0,
	}
}

func (e *kubernetesKubeletConfigApply) BasicDisplayTextForHumans() string {
	return "Update Kubernetes kubelet configuration"
}

func (e *kubernetesKubeletConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(e.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
