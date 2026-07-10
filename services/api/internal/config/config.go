// Package config loads the API's runtime configuration from the environment.
package config

import "os"

// Config is the resolved runtime configuration.
type Config struct {
	// OperatorDSN is the connection string for the erasure path (operator role).
	OperatorDSN string
	// AgentDSN is the connection string for the write/search path (agent_worker role).
	AgentDSN string
	// QueriesDir is the directory holding the named SQL files, loaded at boot.
	QueriesDir string
	// Port is the HTTP listen port.
	Port string
	// CryptodURL is the base URL of the Python crypto microservice.
	CryptodURL string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Load resolves configuration from the environment with sensible fallbacks. The DSN falls back
// through the operator DSN to a single CRDB_DSN and finally to the local insecure cluster, so the
// same binary runs locally and in the cloud.
func Load() Config {
	operator := getenv("CRDB_DSN_OPERATOR", getenv("CRDB_DSN", getenv("CRDB_DSN_LOCAL", "")))
	agent := getenv("CRDB_DSN_AGENT_WORKER", operator)
	return Config{
		OperatorDSN: operator,
		AgentDSN:    agent,
		QueriesDir:  getenv("QUERIES_DIR", "db/queries"),
		Port:        getenv("API_PORT", "8080"),
		CryptodURL:  getenv("CRYPTOD_URL", "http://localhost:8081"),
	}
}
