// Command api is the erasure orchestrator HTTP service.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/agent"
	"github.com/StephenSook/erasure-proof/services/api/internal/config"
	"github.com/StephenSook/erasure-proof/services/api/internal/cryptoclient"
	"github.com/StephenSook/erasure-proof/services/api/internal/demo"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/httpapi"
	"github.com/StephenSook/erasure-proof/services/api/internal/ingest"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	"github.com/StephenSook/erasure-proof/services/api/internal/stream"
)

func main() {
	cfg := config.Load()
	if cfg.OperatorDSN == "" {
		log.Fatal("no database DSN configured (set CRDB_DSN_OPERATOR or CRDB_DSN)")
	}

	startCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := store.Open(startCtx, cfg.OperatorDSN, cfg.AgentDSN, cfg.QueriesDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Fail fast on misconfiguration: pgxpool connects lazily, so verify connectivity and that the
	// query set the erasure path needs is complete, at boot rather than on the first request.
	if err := st.Ping(startCtx); err != nil {
		log.Fatalf("database unreachable: %v", err)
	}
	required := append(append([]string{}, erasure.RequiredQueries...), ingest.RequiredQueries...)
	required = append(required, demo.RequiredQueries...)
	if err := st.Q.Require(required...); err != nil {
		log.Fatalf("query set incomplete: %v", err)
	}
	if st.Agent == st.Operator {
		log.Print("warning: agent and operator share one pool; set CRDB_DSN_AGENT_WORKER to enforce least privilege")
	}

	crypto := cryptoclient.NewHTTP(cfg.CryptodURL)
	orch := erasure.NewOrchestrator(st, crypto)
	ingester := ingest.New(st, crypto)
	demoSvc := demo.New(st, crypto)

	// Wire the live Bedrock forensics agent only when explicitly enabled (AGENTS_LIVE=1), so local
	// and dev runs never reach for AWS credentials. Set it at the judge-facing deploy once the
	// Bedrock token quota is granted; until then the console shows the honest recorded verdict.
	if os.Getenv("AGENTS_LIVE") == "1" {
		converser, cErr := agent.NewBedrockConverse(startCtx)
		if cErr != nil {
			log.Printf("warning: AGENTS_LIVE=1 but Bedrock client init failed, live agent disabled: %v", cErr)
		} else {
			demoSvc.SetForensicsConverser(converser)
			log.Print("live Bedrock forensics agent enabled")
		}
		titan, tErr := agent.NewBedrockTitan(startCtx)
		if tErr != nil {
			log.Printf("warning: AGENTS_LIVE=1 but Titan client init failed, side-by-side embedding disabled: %v", tErr)
		} else {
			demoSvc.SetTitanEmbedder(titan)
			log.Print("live Titan v2 side-by-side embedding enabled")
		}
	}

	// Fallback provider: when Bedrock is not wired (a new AWS account ships with a zero Bedrock
	// quota), an OpenAI-compatible open-model endpoint serves the same agent beats through the
	// same Converser, and every on-screen result is labeled with the provider that answered.
	if demoSvc.ForensicsProvider() == "" && os.Getenv("AGENTS_LLM_URL") != "" {
		oc, oErr := agent.NewOpenAIConverse()
		if oErr != nil {
			log.Printf("warning: AGENTS_LLM_URL set but open-model client init failed: %v", oErr)
		} else {
			demoSvc.SetForensicsConverser(oc)
			demoSvc.SetForensicsProvenance("live_open_model",
				"Live open-model tool-use audit ("+oc.Model()+" via llama.cpp on a Modal serverless "+
					"GPU; Bedrock's new-account quota is zero, so the fallback provider answers). The "+
					"verdict cites only what the read-only tools returned; evidence_proven is our own "+
					"check of the trace.")
			log.Print("live open-model forensics agent enabled (fallback provider)")
		}
	}

	srv := httpapi.New(st, orch, ingester, demoSvc, os.Getenv("GIT_SHA"))

	// One reconcile pass at boot: erasures whose post-commit anchor failed (crash, KMS or S3
	// outage) get their proof anchored at every deploy/restart, so the reconciler is not
	// manual-only. cmd/anchor-reconciler remains for scheduled or ad-hoc runs between restarts.
	go func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer rcancel()
		n, rerr := orch.Reconcile(rctx)
		if rerr != nil {
			log.Printf("boot reconcile: %v", rerr)
			return
		}
		if n > 0 {
			log.Printf("boot reconcile: anchored %d previously un-anchored erasure proof(s)", n)
		}
	}()

	// Live decision-log changefeed -> SSE. The consumer opens its OWN dedicated connection (not the
	// operator pool) so the always-on feed never subtracts a connection from the erasure/read paths.
	// If rangefeeds are disabled the feed just retries and the stream serves the snapshot only.
	// Disable entirely with STREAM_CHANGEFEED=0. Cancelled on shutdown so the connection is closed.
	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()
	if os.Getenv("STREAM_CHANGEFEED") != "0" {
		hub := stream.NewHub(64, 32)
		srv.SetStreamHub(hub)
		consumer := stream.NewConsumer(cfg.OperatorDSN, hub)
		go consumer.Run(streamCtx)
		log.Print("live decision-log changefeed stream enabled")
	}
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown: drain in-flight requests on SIGTERM (Fargate) or SIGINT.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Printf("erasure-proof api listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")
	streamCancel() // stop the changefeed consumer and close its dedicated connection
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
