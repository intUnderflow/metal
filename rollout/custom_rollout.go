package rollout

import (
	"context"
	"github.com/intunderflow/metal/agent/go/actualstate/customrollouts"
	"github.com/intunderflow/metal/config"
)

type customRollout struct {
	nodeID               string
	customRollout        config.CustomRolloutSpec
	customRolloutService customrollouts.CustomRollouts
}

func (c *customRollout) NodeID() string {
	return c.nodeID
}

func (c *customRollout) Apply(ctx context.Context) error {
	return c.customRolloutService.ExecuteApplyCommand(ctx, c.customRollout.ApplyCommand)
}

func (c *customRollout) Priority() Priority {
	return Priority{
		Major: c.customRollout.Priority.Major,
		Minor: c.customRollout.Priority.Minor,
	}
}

func (c *customRollout) BasicDisplayTextForHumans() string {
	return "Custom rollout: " + c.customRollout.BasicDisplayTextForHumans
}

func (c *customRollout) DetailedDisplayTextForHumans() string {
	return "Apply " + c.customRollout.ApplyCommand
}
