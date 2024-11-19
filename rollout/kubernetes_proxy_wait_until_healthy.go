package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/kubernetes/proxy"
)

type kubernetesProxyWaitUntilHealthy struct {
	nodeID        string
	currentStatus string
	proxyService  proxy.Proxy
}

func (e *kubernetesProxyWaitUntilHealthy) NodeID() string {
	return e.nodeID
}

func (e *kubernetesProxyWaitUntilHealthy) Apply(ctx context.Context) error {
	return e.proxyService.RestartService(ctx)
}

func (e *kubernetesProxyWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 19,
		Minor: 1,
	}
}

func (e *kubernetesProxyWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for Kubernetes proxy to become healthy"
}

func (e *kubernetesProxyWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", e.currentStatus)
}
