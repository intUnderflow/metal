package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/wireguard"
	"github.com/intunderflow/metal/config"
)

type wireguardConfigApply struct {
	nodeID           string
	specToApply      *config.WireguardSpec
	wireguardService wireguard.Wireguard
}

func (w *wireguardConfigApply) NodeID() string {
	return w.nodeID
}

func (w *wireguardConfigApply) Apply(_ context.Context) error {
	return w.wireguardService.ApplySpec(w.specToApply)
}

func (w *wireguardConfigApply) Priority() Priority {
	return Priority{
		Major: 10,
		Minor: 0,
	}
}

func (w *wireguardConfigApply) BasicDisplayTextForHumans() string {
	return "Update Wireguard configuration"
}

func (w *wireguardConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(w.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
