package handlers

import (
	"fmt"
	"github.com/intunderflow/metal/broker/go/lib"
	"github.com/intunderflow/metal/config"
	"github.com/intunderflow/metal/crypto"
	"github.com/intunderflow/metal/wrapper"
	"net/http"
)

func NewSetNodeActualState(verifier crypto.Verifier, wrapper *wrapper.ConfigWrapper) SetNodeActualState {
	return SetNodeActualState{
		verifier: verifier,
		wrapper:  wrapper,
	}
}

type SetNodeActualState struct {
	verifier crypto.Verifier
	wrapper  *wrapper.ConfigWrapper
}

type SetNodeActualStateRequest struct {
	ActualState *config.NodeActualState `json:"actual_state"`
	Signature   *crypto.Signature       `json:"signature"`
}

func (h SetNodeActualState) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	var request SetNodeActualStateRequest
	err := lib.UnmarshalRequest(r, &request)
	if err != nil {
		return err
	}

	err = h.verifier.Verify(request.Signature, request.ActualState, request.ActualState.ID+".node.metal.local")
	if err != nil {
		return err
	}

	h.wrapper.Mutex.Lock()
	defer h.wrapper.Mutex.Unlock()

	node, ok := h.wrapper.Config.Nodes[request.ActualState.ID]
	if !ok {
		return fmt.Errorf("no such node: %s", request.ActualState.ID)
	} else if node.ActualState != nil {
		latestVersion := node.ActualState.CreatedAt
		if latestVersion.After(request.ActualState.CreatedAt) {
			return fmt.Errorf(
				"node %s is already at a more recent version %s, sent version %s",
				request.ActualState.ID,
				node.ActualState.CreatedAt.GoString(),
				request.ActualState.CreatedAt.GoString(),
			)
		}
	}
	node.ActualState = request.ActualState
	node.ActualStateSignature = request.Signature
	return nil
}
