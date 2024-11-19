package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/agent/go/actualstate/dns"
	"github.com/intunderflow/metal/config"
)

type dnsConfigApply struct {
	nodeID      string
	specToApply *config.DNSSpec
	dnsService  dns.DNS
}

func (d *dnsConfigApply) NodeID() string {
	return d.nodeID
}

func (d *dnsConfigApply) Apply(_ context.Context) error {
	return d.dnsService.ApplySpec(d.specToApply)
}

func (d *dnsConfigApply) Priority() Priority {
	return Priority{
		Major: 10,
		Minor: 2,
	}
}

func (d *dnsConfigApply) BasicDisplayTextForHumans() string {
	return "Update DNS configuration"
}

func (d *dnsConfigApply) DetailedDisplayTextForHumans() string {
	marshalled, err := json.MarshalIndent(d.specToApply, "", "  ")
	if err != nil {
		return fmt.Sprintf("error %e", err)
	}
	return string(marshalled)
}
