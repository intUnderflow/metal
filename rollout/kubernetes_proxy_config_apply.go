package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/proxy"
	"github.com/intunderflow/metal/config"
)

type kubernetesProxyConfigApply struct {
	nodeID       string
	specToApply  *config.KubernetesProxySpec
	proxyService proxy.Proxy
}

func (e *kubernetesProxyConfigApply) NodeID() string {
	return e.nodeID
}

func (e *kubernetesProxyConfigApply) Apply(_ context.Context) error {
	return e.proxyService.ApplySpec(e.specToApply)
}

func (e *kubernetesProxyConfigApply) Priority() Priority {
	return Priority{
		Major: 19,
		Minor: 0,
	}
}

func (e *kubernetesProxyConfigApply) BasicDisplayTextForHumans() string {
	return "Update Kubernetes proxy configuration"
}

func (e *kubernetesProxyConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(e.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
