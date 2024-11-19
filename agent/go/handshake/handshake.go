package handshake

import (
	"context"
	"fmt"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"github.com/intunderflow/metal/net"
)

func NewHandshake(broker net.Broker, verifier crypto.Verifier) Handshake {
	return &handshakeImpl{
		broker:   broker,
		verifier: verifier,
	}
}

type Handshake interface {
	PullAndPush(context.Context, *config.Config) error
	Pull(context.Context, *config.Config) error
	Push(context.Context, *config.Config) error
}

type handshakeImpl struct {
	broker   net.Broker
	verifier crypto.Verifier
}

func (h *handshakeImpl) PullAndPush(ctx context.Context, ourConfig *config.Config) error {
	cfg, err := h.broker.GetConfig(ctx)
	if err != nil {
		return err
	}
	err = h.pullInner(ctx, ourConfig, cfg)
	if err != nil {
		return err
	}
	err = h.pushInner(ctx, ourConfig, cfg)
	if err != nil {
		return err
	}
	return nil
}

func (h *handshakeImpl) Pull(ctx context.Context, ourConfig *config.Config) error {
	cfg, err := h.broker.GetConfig(ctx)
	if err != nil {
		return err
	}

	return h.pullInner(ctx, ourConfig, cfg)
}

func (h *handshakeImpl) pullInner(ctx context.Context, ourConfig *config.Config, remoteConfig *config.Config) error {
	for claimedID, node := range remoteConfig.Nodes {
		err := node.Verify(claimedID, h.verifier)
		if err != nil {
			fmt.Printf("not accepting node %s as verification failed with %v\n", claimedID, err)
			continue
		}

		existingNode, ok := ourConfig.Nodes[claimedID]
		if !ok {
			fmt.Printf("accepting new node %s\n", claimedID)
			ourConfig.Nodes[claimedID] = node
			continue
		}

		if node.GoalState.CreatedAt.After(existingNode.GoalState.CreatedAt) {
			fmt.Printf("updating goal state for node %s to %s\n", claimedID, node.GoalState.CreatedAt.String())
			existingNode.GoalState = node.GoalState
			existingNode.GoalStateSignature = node.GoalStateSignature
		}

		if (node.ActualState != nil && existingNode.ActualState == nil) ||
			(node.ActualState != nil && existingNode.ActualState != nil && existingNode.ActualState.CreatedAt.Before(node.ActualState.CreatedAt)) {
			fmt.Printf("updating actual state for node %s to %s\n", claimedID, node.ActualState.CreatedAt.String())
			existingNode.ActualState = node.ActualState
			existingNode.ActualStateSignature = node.ActualStateSignature
		}
	}
	return nil
}

func (h *handshakeImpl) Push(ctx context.Context, ourConfig *config.Config) error {
	cfg, err := h.broker.GetConfig(ctx)
	if err != nil {
		return err
	}

	return h.pushInner(ctx, ourConfig, cfg)
}

func (h *handshakeImpl) pushInner(ctx context.Context, ourConfig *config.Config, remoteConfig *config.Config) error {
	nodeGoalStatesToPush := h.getNodeGoalStatesToPush(ourConfig, remoteConfig)
	for _, node := range nodeGoalStatesToPush {
		err := h.broker.SetNodeGoalState(ctx, node.goalState, node.signature)
		if err != nil {
			fmt.Printf("failed to push node goal state for node %s: %v\n", node.goalState.ID, err)
		}
	}
	nodeActualStatesToPush := h.getNodeActualStatesToPush(ourConfig, remoteConfig)
	for _, node := range nodeActualStatesToPush {
		err := h.broker.SetNodeActualState(ctx, node.actualState, node.signature)
		if err != nil {
			fmt.Printf("failed to push node actual state for node %s: %v\n", node.actualState.ID, err)
		}
	}
	return nil
}

type goalStateWithSignature struct {
	goalState *config.NodeGoalState
	signature *crypto.Signature
}

func (h *handshakeImpl) getNodeGoalStatesToPush(ourConfig *config.Config, remoteConfig *config.Config) map[string]goalStateWithSignature {
	goalStatesToPush := map[string]goalStateWithSignature{}

	for id, node := range ourConfig.Nodes {
		existingRemoteNode, ok := remoteConfig.Nodes[id]
		if !ok {
			goalStatesToPush[id] = goalStateWithSignature{
				goalState: node.GoalState,
				signature: node.GoalStateSignature,
			}
			continue
		}

		if existingRemoteNode.GoalState.CreatedAt.Before(node.GoalState.CreatedAt) {
			goalStatesToPush[id] = goalStateWithSignature{
				goalState: node.GoalState,
				signature: node.GoalStateSignature,
			}
		}
	}

	return goalStatesToPush
}

type actualStateWithSignature struct {
	actualState *config.NodeActualState
	signature   *crypto.Signature
}

func (h *handshakeImpl) getNodeActualStatesToPush(ourConfig *config.Config, remoteConfig *config.Config) map[string]actualStateWithSignature {
	actualStatesToPush := map[string]actualStateWithSignature{}

	for id, node := range ourConfig.Nodes {
		if node.ActualState == nil {
			continue
		}
		existingRemoteNode, ok := remoteConfig.Nodes[id]
		if !ok {
			actualStatesToPush[id] = actualStateWithSignature{
				actualState: node.ActualState,
				signature:   node.ActualStateSignature,
			}
			continue
		}

		if existingRemoteNode.ActualState == nil {
			actualStatesToPush[id] = actualStateWithSignature{
				actualState: node.ActualState,
				signature:   node.ActualStateSignature,
			}
			continue
		}

		if existingRemoteNode.ActualState.CreatedAt.Before(node.ActualState.CreatedAt) {
			actualStatesToPush[id] = actualStateWithSignature{
				actualState: node.ActualState,
				signature:   node.ActualStateSignature,
			}
		}
	}

	return actualStatesToPush
}
