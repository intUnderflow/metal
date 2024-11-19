package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/etcd"
	"github.com/intunderflow/metal/config"
)

type etcdConfigApply struct {
	nodeID      string
	specToApply *config.EtcdSpec
	etcdService etcd.Etcd
}

func (e *etcdConfigApply) NodeID() string {
	return e.nodeID
}

func (e *etcdConfigApply) Apply(_ context.Context) error {
	return e.etcdService.ApplySpec(e.specToApply)
}

func (e *etcdConfigApply) Priority() Priority {
	return Priority{
		Major: 11,
		Minor: 0,
	}
}

func (e *etcdConfigApply) BasicDisplayTextForHumans() string {
	return "Update etcd configuration"
}

func (e *etcdConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(e.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
