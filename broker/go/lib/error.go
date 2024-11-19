package lib

import (
	"fmt"
	"net/http"
)

func HandleError(w http.ResponseWriter, r *http.Request, err error) {
	fmt.Printf("Error handling request for %s: %s\n", r.URL, err.Error())
	http.Error(w, err.Error(), 500)
}
