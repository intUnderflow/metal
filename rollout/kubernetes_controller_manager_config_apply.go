package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	controller_manager "github.com/intunderflow/metal/agent/go/actualstate/kubernetes/controller-manager"
	"github.com/intunderflow/metal/config"
)

type kubernetesControllerManagerConfigApply struct {
	nodeID                             string
	specToApply                        *config.KubernetesControllerManagerSpec
	kubernetesControllerManagerService controller_manager.ControllerManager
}

func (e *kubernetesControllerManagerConfigApply) NodeID() string {
	return e.nodeID
}

func (e *kubernetesControllerManagerConfigApply) Apply(_ context.Context) error {
	return e.kubernetesControllerManagerService.ApplySpec(e.specToApply)
}

func (e *kubernetesControllerManagerConfigApply) Priority() Priority {
	return Priority{
		Major: 13,
		Minor: 0,
	}
}

func (e *kubernetesControllerManagerConfigApply) BasicDisplayTextForHumans() string {
	return "Update Kubernetes controller manager configuration"
}

func (e *kubernetesControllerManagerConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(e.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
