package lib

import (
	"encoding/json"
	"io"
	"net/http"
)

func UnmarshalRequest(request *http.Request, to any) error {
	requestBytes, err := io.ReadAll(request.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(requestBytes, to)
	if err != nil {
		return err
	}

	return nil
}
