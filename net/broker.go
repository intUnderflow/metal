package net

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/intunderflow/metal/broker/go/handlers"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"io"
	"net/http"
)

type Broker interface {
	GetConfig(context.Context) (*config.Config, error)
	ListNodes(context.Context) (map[string]*config.Node, error)
	SetNodeGoalState(context.Context, *config.NodeGoalState, *crypto.Signature) error
	SetNodeActualState(context.Context, *config.NodeActualState, *crypto.Signature) error
}

func NewBroker(address string, client *http.Client) Broker {
	return &brokerImpl{
		address: address,
		client:  client,
	}
}

type brokerImpl struct {
	address string
	client  *http.Client
}

func (b *brokerImpl) GetConfig(ctx context.Context) (*config.Config, error) {
	response, err := b.client.Get(b.address + "/v1/get_config")
	if err != nil {
		return nil, err
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	cfg, err := config.FromBytes(responseBytes)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (b *brokerImpl) ListNodes(ctx context.Context) (map[string]*config.Node, error) {
	cfg, err := b.GetConfig(ctx)
	if err != nil {
		return nil, err
	}

	return cfg.Nodes, nil
}

func (b *brokerImpl) SetNodeGoalState(ctx context.Context, goalState *config.NodeGoalState, signature *crypto.Signature) error {
	request := handlers.SetNodeGoalStateRequest{
		GoalState: goalState,
		Signature: signature,
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	response, err := b.client.Post(b.address+"/v1/set_node_goal_state", "text/json", bytes.NewReader(requestBytes))
	if err != nil {
		return err
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode < 200 || response.StatusCode > 399 {
		return fmt.Errorf("response status is %d %s %s", response.StatusCode, response.Status, string(responseBytes))
	}

	return nil
}

func (b *brokerImpl) SetNodeActualState(ctx context.Context, actualState *config.NodeActualState, signature *crypto.Signature) error {
	request := handlers.SetNodeActualStateRequest{
		ActualState: actualState,
		Signature:   signature,
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	response, err := b.client.Post(b.address+"/v1/set_node_actual_state", "text/json", bytes.NewReader(requestBytes))
	if err != nil {
		return err
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode < 200 || response.StatusCode > 399 {
		return fmt.Errorf("response status is %d %s %s", response.StatusCode, response.Status, string(responseBytes))
	}

	return nil
}
