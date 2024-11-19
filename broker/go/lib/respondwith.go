package lib

import (
	"encoding/json"
	"net/http"
)

func RespondWithJSON(response any, writer http.ResponseWriter) error {
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return err
	}

	writer.Header().Set("content-type", "text/json")
	_, err = writer.Write(responseBytes)
	if err != nil {
		return err
	}

	return nil
}
