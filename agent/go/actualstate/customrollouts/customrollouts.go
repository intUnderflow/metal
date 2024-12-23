package customrollouts

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/config"
	"os/exec"
	"sync"
)

type CustomRollouts interface {
	SetKnownCustomRollouts(map[string]config.CustomRolloutSpec)
	ExecuteApplyCommand(context.Context, string) error
	GetActualState(context.Context) map[string]string
}

func NewCustomRollouts() CustomRollouts {
	return &customRollouts{
		mutex:               &sync.RWMutex{},
		knownCustomRollouts: map[string]config.CustomRolloutSpec{},
	}
}

type customRollouts struct {
	mutex               *sync.RWMutex
	knownCustomRollouts map[string]config.CustomRolloutSpec
}

func (c *customRollouts) SetKnownCustomRollouts(new map[string]config.CustomRolloutSpec) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.knownCustomRollouts = new
}

func (c *customRollouts) GetActualState(ctx context.Context) map[string]string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	results := map[string]string{}
	for id, entry := range c.knownCustomRollouts {
		actualState, err := c.executeGetActualStateCommand(ctx, entry.GetActualStateCommand)
		if err != nil {
			fmt.Printf("error getting actual state for custom rollout %s: %v\n", id, err)
			continue
		}
		results[id] = actualState
	}
	return results
}

func (c *customRollouts) executeGetActualStateCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	if cmd.Err != nil {
		return "", cmd.Err
	}

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (c *customRollouts) ExecuteApplyCommand(ctx context.Context, command string) error {
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	if cmd.Err != nil {
		return cmd.Err
	}

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
