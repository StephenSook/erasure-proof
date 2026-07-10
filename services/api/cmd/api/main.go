// Command api is the erasure orchestrator HTTP service.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/config"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/httpapi"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
)

func main() {
	cfg := config.Load()
	if cfg.OperatorDSN == "" {
		log.Fatal("no database DSN configured (set CRDB_DSN_OPERATOR or CRDB_DSN)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := store.Open(ctx, cfg.OperatorDSN, cfg.AgentDSN, cfg.QueriesDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	srv := httpapi.New(st, erasure.New(st), os.Getenv("GIT_SHA"))
	addr := ":" + cfg.Port
	log.Printf("erasure-proof api listening on %s", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
