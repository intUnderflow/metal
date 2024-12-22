package rollout

import (
	"context"
	"github.com/intunderflow/metal/agent/go/actualstate/extradata"
)

type extraDataApply struct {
	nodeID           string
	extraData        map[string]string
	extraDataService extradata.ExtraData
}

func (e *extraDataApply) NodeID() string {
	return e.nodeID
}

func (e *extraDataApply) Apply(_ context.Context) error {
	return e.extraDataService.ApplyExtraData(e.extraData)
}

func (e *extraDataApply) Priority() Priority {
	return Priority{
		Major: 20,
		Minor: 0,
	}
}

func (e *extraDataApply) BasicDisplayTextForHumans() string {
	return "Apply extra data"
}

func (e *extraDataApply) DetailedDisplayTextForHumans() string {
	return "Apply extra data"
}
