package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/scheduler"
)

type kubernetesSchedulerWaitUntilHealthy struct {
	nodeID                     string
	currentStatus              string
	kubernetesSchedulerService scheduler.Scheduler
}

func (e *kubernetesSchedulerWaitUntilHealthy) NodeID() string {
	return e.nodeID
}

func (e *kubernetesSchedulerWaitUntilHealthy) Apply(ctx context.Context) error {
	return e.kubernetesSchedulerService.RestartService(ctx)
}

func (e *kubernetesSchedulerWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 14,
		Minor: 1,
	}
}

func (e *kubernetesSchedulerWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for Kubernetes scheduler to become healthy"
}

func (e *kubernetesSchedulerWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", e.currentStatus)
}
