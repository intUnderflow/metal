package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/scheduler"
	"github.com/intunderflow/metal/config"
)

type kubernetesSchedulerConfigApply struct {
	nodeID                     string
	specToApply                *config.KubernetesSchedulerSpec
	kubernetesSchedulerService scheduler.Scheduler
}

func (e *kubernetesSchedulerConfigApply) NodeID() string {
	return e.nodeID
}

func (e *kubernetesSchedulerConfigApply) Apply(_ context.Context) error {
	return e.kubernetesSchedulerService.ApplySpec(e.specToApply)
}

func (e *kubernetesSchedulerConfigApply) Priority() Priority {
	return Priority{
		Major: 13,
		Minor: 0,
	}
}

func (e *kubernetesSchedulerConfigApply) BasicDisplayTextForHumans() string {
	return "Update Kubernetes scheduler configuration"
}

func (e *kubernetesSchedulerConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(e.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
