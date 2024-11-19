package handlers

import (
	"fmt"
	"github.com/intunderflow/metal/broker/go/lib"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"github.com/intunderflow/metal/wrapper"
	"net/http"
)

func NewSetNodeGoalState(verifier crypto.Verifier, wrapper *wrapper.ConfigWrapper) SetNodeGoalState {
	return SetNodeGoalState{
		verifier: verifier,
		wrapper:  wrapper,
	}
}

type SetNodeGoalState struct {
	verifier crypto.Verifier
	wrapper  *wrapper.ConfigWrapper
}

type SetNodeGoalStateRequest struct {
	GoalState *config.NodeGoalState `json:"goal_state"`
	Signature *crypto.Signature     `json:"signature"`
}

func (h SetNodeGoalState) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	var request SetNodeGoalStateRequest
	err := lib.UnmarshalRequest(r, &request)
	if err != nil {
		return err
	}

	err = h.verifier.Verify(request.Signature, request.GoalState, ".admin.metal.local")
	if err != nil {
		return err
	}

	h.wrapper.Mutex.Lock()
	defer h.wrapper.Mutex.Unlock()

	node, ok := h.wrapper.Config.Nodes[request.GoalState.ID]
	if !ok {
		node = &config.Node{}
		h.wrapper.Config.Nodes[request.GoalState.ID] = node
	} else {
		latestVersion := node.GoalState.CreatedAt
		if latestVersion.After(request.GoalState.CreatedAt) {
			return fmt.Errorf(
				"node %s is already at a more recent version %s, sent version %s",
				request.GoalState.ID,
				node.GoalState.CreatedAt.GoString(),
				request.GoalState.CreatedAt.GoString(),
			)
		}
	}
	node.GoalState = request.GoalState
	node.GoalStateSignature = request.Signature
	return nil
}
