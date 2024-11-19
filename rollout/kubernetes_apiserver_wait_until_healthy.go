package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/apiserver"
)

type kubernetesAPIServerWaitUntilHealthy struct {
	nodeID                     string
	currentStatus              string
	kubernetesAPIServerService apiserver.ApiServer
}

func (e *kubernetesAPIServerWaitUntilHealthy) NodeID() string {
	return e.nodeID
}

func (e *kubernetesAPIServerWaitUntilHealthy) Apply(ctx context.Context) error {
	return e.kubernetesAPIServerService.RestartService(ctx)
}

func (e *kubernetesAPIServerWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 12,
		Minor: 1,
	}
}

func (e *kubernetesAPIServerWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for Kubernetes API server to become healthy"
}

func (e *kubernetesAPIServerWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", e.currentStatus)
}
