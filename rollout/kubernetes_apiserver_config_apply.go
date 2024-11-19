package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/apiserver"
	"github.com/intunderflow/metal/config"
)

type kubernetesAPIServerConfigApply struct {
	nodeID                     string
	specToApply                *config.KubernetesAPIServerSpec
	kubernetesAPIServerService apiserver.ApiServer
}

func (e *kubernetesAPIServerConfigApply) NodeID() string {
	return e.nodeID
}

func (e *kubernetesAPIServerConfigApply) Apply(_ context.Context) error {
	return e.kubernetesAPIServerService.ApplySpec(e.specToApply)
}

func (e *kubernetesAPIServerConfigApply) Priority() Priority {
	return Priority{
		Major: 12,
		Minor: 0,
	}
}

func (e *kubernetesAPIServerConfigApply) BasicDisplayTextForHumans() string {
	return "Update Kubernetes API server configuration"
}

func (e *kubernetesAPIServerConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(e.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
