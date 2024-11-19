package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/coredns"
	"github.com/intunderflow/metal/config"
)

type coreDNSConfigApply struct {
	nodeID         string
	specToApply    *config.CoreDNSSpec
	coreDNSService coredns.CoreDNS
}

func (c *coreDNSConfigApply) NodeID() string {
	return c.nodeID
}

func (c *coreDNSConfigApply) Apply(_ context.Context) error {
	return c.coreDNSService.ApplySpec(c.specToApply)
}

func (c *coreDNSConfigApply) Priority() Priority {
	return Priority{
		Major: 15,
		Minor: 0,
	}
}

func (c *coreDNSConfigApply) BasicDisplayTextForHumans() string {
	return "Update CoreDNS configuration"
}

func (c *coreDNSConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(c.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
