package rollout

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/wireguard"
)

type wireguardWaitUntilHealthy struct {
	nodeID           string
	currentStatus    string
	wireguardService wireguard.Wireguard
}

func (w *wireguardWaitUntilHealthy) NodeID() string {
	return w.nodeID
}

func (w *wireguardWaitUntilHealthy) Apply(ctx context.Context) error {
	return w.wireguardService.RestartService(ctx)
}

func (w *wireguardWaitUntilHealthy) Priority() Priority {
	return Priority{
		Major: 10,
		Minor: 1,
	}
}

func (w *wireguardWaitUntilHealthy) BasicDisplayTextForHumans() string {
	return "Wait for Wireguard to become healthy"
}

func (w *wireguardWaitUntilHealthy) DetailedDisplayTextForHumans() string {
	return fmt.Sprintf("Current status is %s, service must be healthy", w.currentStatus)
}
