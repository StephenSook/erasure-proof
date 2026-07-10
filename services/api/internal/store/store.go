package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store holds the role-scoped connection pools and the loaded queries. The operator pool runs the
// erasure path; the agent pool runs the write/search path. Binding pools to distinct SQL roles is
// the least-privilege story inside one binary.
type Store struct {
	Operator *pgxpool.Pool
	Agent    *pgxpool.Pool
	Q        Queries
}

// Open creates both pools and loads the named queries. If the agent DSN equals the operator DSN
// the same pool is shared.
func Open(ctx context.Context, operatorDSN, agentDSN, queriesDir string) (*Store, error) {
	q, err := LoadQueries(queriesDir)
	if err != nil {
		return nil, fmt.Errorf("load queries: %w", err)
	}
	operator, err := pgxpool.New(ctx, operatorDSN)
	if err != nil {
		return nil, fmt.Errorf("operator pool: %w", err)
	}
	agent := operator
	if agentDSN != "" && agentDSN != operatorDSN {
		agent, err = pgxpool.New(ctx, agentDSN)
		if err != nil {
			operator.Close()
			return nil, fmt.Errorf("agent pool: %w", err)
		}
	}
	return &Store{Operator: operator, Agent: agent, Q: q}, nil
}

// Ping checks operator-pool connectivity (used by the health check and as a cluster keepalive).
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.Operator.QueryRow(ctx, "SELECT 1").Scan(&one)
}

// Close releases both pools.
func (s *Store) Close() {
	if s.Agent != nil && s.Agent != s.Operator {
		s.Agent.Close()
	}
	if s.Operator != nil {
		s.Operator.Close()
	}
}
