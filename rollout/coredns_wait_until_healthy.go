package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/coredns"
)

type coreDNSWaitUntilHealthy struct {
	nodeID         string
	currentStatus  string
	coreDNSService coredns.CoreDNS
}

func (c *coreDNSWaitUntilHealthy) NodeID() string {
	return c.nodeID
}

func (c *coreDNSWaitUntilHealthy) Apply(ctx context.Context) error {
	return c.coreDNSService.RestartService(ctx)
}

func (c *coreDNSWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 15,
		Minor: 1,
	}
}

func (c *coreDNSWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for CoreDNS to become healthy"
}

func (c *coreDNSWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", c.currentStatus)
}
