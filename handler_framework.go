package main

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
)

func authorize(w http.ResponseWriter, r *http.Request) bool {
	key := r.Header.Get("X-API-Key")
	if !ApiKeys.Enabled {
		return true
	}
	return ApiKeys.IsAuthorized(key)
}

// Unified method validator
func validateMethod(w http.ResponseWriter, r *http.Request, expectedMethod string) bool {
	if r.Method != expectedMethod {
		Logger.Debug("Rejected request due to invalid HTTP method",
			"received_method", r.Method,
			"expected_method", expectedMethod,
			"endpoint", r.URL.Path,
		)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// Unified request decoder
func decodeJSONRequest(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		Logger.Warn("Invalid JSON body",
			"error", err,
			"status", http.StatusBadRequest,
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
		)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

// Unified response writer
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		Logger.Error("Failed to encode response",
			"error", err,
			"stack", string(debug.Stack()),
		)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
