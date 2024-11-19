package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/kubelet"
)

type kubernetesKubeletWaitUntilHealthy struct {
	nodeID         string
	currentStatus  string
	kubeletService kubelet.Kubelet
}

func (e *kubernetesKubeletWaitUntilHealthy) NodeID() string {
	return e.nodeID
}

func (e *kubernetesKubeletWaitUntilHealthy) Apply(ctx context.Context) error {
	return e.kubeletService.RestartService(ctx)
}

func (e *kubernetesKubeletWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 18,
		Minor: 1,
	}
}

func (e *kubernetesKubeletWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for Kubernetes kubelet to become healthy"
}

func (e *kubernetesKubeletWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", e.currentStatus)
}
