package main

import (
	"encoding/json"
	"net/http"
)

// H is a shorthand for map[string]any
type H map[string]any

// writeJSON writes JSON data to the response body.
// return the error by Encoder.Encode if it fails.
func writeJSON(w http.ResponseWriter, code int, header http.Header, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	for k, v := range header {
		w.Header()[k] = v
	}

	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(data)
}
