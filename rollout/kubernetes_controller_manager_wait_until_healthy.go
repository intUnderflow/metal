package rollout

import (
	"context"
	"fmt"
	controller_manager "github.com/intunderflow/metal/agent/go/actualstate/kubernetes/controller-manager"
)

type kubernetesControllerManagerWaitUntilHealthy struct {
	nodeID                             string
	currentStatus                      string
	kubernetesControllerManagerService controller_manager.ControllerManager
}

func (e *kubernetesControllerManagerWaitUntilHealthy) NodeID() string {
	return e.nodeID
}

func (e *kubernetesControllerManagerWaitUntilHealthy) Apply(ctx context.Context) error {
	return e.kubernetesControllerManagerService.RestartService(ctx)
}

func (e *kubernetesControllerManagerWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 13,
		Minor: 1,
	}
}

func (e *kubernetesControllerManagerWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for Kubernetes controller manager to become healthy"
}

func (e *kubernetesControllerManagerWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", e.currentStatus)
}
