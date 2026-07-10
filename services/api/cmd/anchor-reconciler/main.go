// Command anchor-reconciler anchors erasure proofs that were never recorded (a crash or a failed
// post-commit anchor). It is a one-shot: a scheduled job runs it periodically. It never re-erases
// anything; it only anchors the proof for an already-committed erasure whose proof_ref is NULL.
package main

import (
	"context"
	"log"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/config"
	"github.com/StephenSook/erasure-proof/services/api/internal/cryptoclient"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
)

func main() {
	cfg := config.Load()
	if cfg.OperatorDSN == "" {
		log.Fatal("no database DSN configured (set CRDB_DSN_OPERATOR or CRDB_DSN)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := store.Open(ctx, cfg.OperatorDSN, cfg.AgentDSN, cfg.QueriesDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Q.Require(erasure.RequiredQueries...); err != nil {
		log.Fatalf("query set incomplete: %v", err)
	}

	orch := erasure.NewOrchestrator(st, cryptoclient.NewHTTP(cfg.CryptodURL))
	n, err := orch.Reconcile(ctx)
	if err != nil {
		log.Fatalf("reconcile: %v", err)
	}
	log.Printf("anchor-reconciler: anchored %d previously un-anchored erasure proof(s)", n)
}
