package config

import (
	"os"
)

// GetEnv gets an environment variable. If it doesn't exists, returns the fallback
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
