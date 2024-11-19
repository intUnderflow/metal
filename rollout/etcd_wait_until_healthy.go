package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/etcd"
)

type etcdWaitUntilHealthy struct {
	nodeID        string
	currentStatus string
	etcdService   etcd.Etcd
}

func (e *etcdWaitUntilHealthy) NodeID() string {
	return e.nodeID
}

func (e *etcdWaitUntilHealthy) Apply(ctx context.Context) error {
	return e.etcdService.RestartService(ctx)
}

func (e *etcdWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 11,
		Minor: 1,
	}
}

func (e *etcdWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for etcd to become healthy"
}

func (e *etcdWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", e.currentStatus)
}
