package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
)

func Middleware(expectedMethod string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authenticate(w, r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !validateMethod(w, r, expectedMethod) {
			return
		}

		next.ServeHTTP(w, r)
	}
}
func authenticate(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.Header == nil {
		return false
	}
	key := r.Header.Get("X-API-Key")

	if Config.HashedApiKeysPath == "" { // Authentication is disabled
		return true
	}
	y := ApiKeys.IsAuthenticated(key)
	fmt.Printf("key = %s, authenticated = %t\n", key, y)

	return y
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
