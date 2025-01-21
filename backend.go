package main

import "fmt"

type MapOperations interface {
	Add(key, value string)
	Remove(key string)
	Lookup(key string) (string, bool)
	List()
}

type RevocationList struct {
	data map[string]string
}

// NewMapWrapper creates a new instance of MapWrapper
func NewMapWrapper() *RevocationList {
	return &RevocationList{
		data: make(map[string]string),
	}
}

// Add inserts a key-value pair into the map
func (m *RevocationList) Add(key, value string) {
	m.data[key] = value
	fmt.Printf("Added: %s -> %s\n", key, value)
}

// Remove deletes a key-value pair from the map
func (m *RevocationList) Remove(key string) {
	if _, exists := m.data[key]; exists {
		delete(m.data, key)
		fmt.Printf("Removed: %s\n", key)
	} else {
		fmt.Printf("Key '%s' not found\n", key)
	}
}

// Lookup retrieves the value associated with a key
func (m *RevocationList) Lookup(key string) (string, bool) {
	value, exists := m.data[key]
	return value, exists
}
