// Package httpapi exposes the erasure orchestrator over HTTP.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/demo"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/ingest"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
)

// Server wires the store, the ingest path, the erasure orchestrator, and the read-only demo gateway
// to HTTP handlers.
type Server struct {
	store    *store.Store
	orch     *erasure.Orchestrator
	ingester *ingest.Ingester
	demo     *demo.Service
	commit   string // the deployed git SHA, echoed by /healthz so we can prove what is served
}

// New builds a Server.
func New(s *store.Store, orch *erasure.Orchestrator, ingester *ingest.Ingester, dsvc *demo.Service, commit string) *Server {
	return &Server{store: s, orch: orch, ingester: ingester, demo: dsvc, commit: commit}
}

// Routes returns the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /memories", s.handleIngest)
	mux.HandleFunc("POST /erase", s.handleErase)
	// Read-only demo gateway (the browser-facing six-stage console).
	mux.HandleFunc("GET /api/memory", s.handleDemoMemory)
	mux.HandleFunc("GET /api/proof", s.handleDemoProof)
	mux.HandleFunc("GET /api/decision-log", s.handleDemoDecisionLog)
	mux.HandleFunc("GET /api/inversion", s.handleDemoInversion)
	mux.HandleFunc("POST /api/verify-chain", s.handleDemoVerifyChain)
	mux.HandleFunc("POST /api/rbac-demo", s.handleDemoRbac)
	mux.HandleFunc("GET /api/tree-head", s.handleDemoTreeHead)
	mux.HandleFunc("GET /api/inclusion", s.handleDemoInclusion)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line is already flushed, so a failed encode cannot change the response; log it so
	// a lost success confirmation still leaves a server-side trace.
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("httpapi: response encode failed: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	dbOK := true
	if err := s.store.Ping(ctx); err != nil {
		dbOK = false
		log.Printf("httpapi: health ping failed: %v", err)
	}
	status := http.StatusOK
	if !dbOK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ok": dbOK, "db": dbOK, "commit": s.commit})
}

type memoryRequest struct {
	SubjectID string `json:"subject_id"` // optional; a new UUID is minted when empty
	Content   string `json:"content"`    // base64 plaintext
	Embedding string `json:"embedding"`  // base64 of the raw little-endian float32 GTR vector (768 dims)
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var req memoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("httpapi: malformed memory request body: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed JSON body"})
		return
	}
	if req.Content == "" || req.Embedding == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content and embedding required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	res, err := s.ingester.Ingest(ctx, req.SubjectID, req.Content, req.Embedding)
	switch {
	case errors.Is(err, ingest.ErrSubjectErased):
		// Refusing to resurrect an erased subject is a deliberate guarantee, not a server fault.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "subject erased; cannot re-add memory"})
		return
	case errors.Is(err, ingest.ErrAlreadyProvisioned):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "subject already provisioned"})
		return
	case errors.Is(err, ingest.ErrBadEmbedding), errors.Is(err, ingest.ErrBadContent),
		errors.Is(err, ingest.ErrBadSubjectID):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	case err != nil:
		log.Printf("httpapi: ingest failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ingest failed"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type eraseRequest struct {
	SubjectID   string `json:"subject_id"`
	LawfulBasis string `json:"lawful_basis"`
}

func (s *Server) handleErase(w http.ResponseWriter, r *http.Request) {
	var req eraseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("httpapi: malformed erase request body: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed JSON body"})
		return
	}
	if req.SubjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id required"})
		return
	}

	// Validate the lawful basis at the boundary before it is ever hashed into the permanent log.
	basis := erasure.LawfulBasis(req.LawfulBasis)
	if req.LawfulBasis == "" {
		basis = erasure.LawfulBasisGDPRArt17
	}
	if !basis.Valid() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown lawful_basis"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// EraseAndAnchor commits the erasure, then anchors the signed proof post-commit. If anchoring
	// fails the erasure is still durably done (res is populated); the reconciler will anchor later.
	res, proofRef, err := s.orch.EraseAndAnchor(ctx, req.SubjectID, basis)
	switch {
	case errors.Is(err, erasure.ErrAlreadyErased):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already erased"})
		return
	case errors.Is(err, erasure.ErrSubjectNotFound):
		log.Print("httpapi: erase requested for unknown subject")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown subject"})
		return
	case err != nil && res.Seq == 0:
		// The erasure transaction itself failed: nothing was erased.
		log.Printf("httpapi: erase failed (basis=%s): %v", basis, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "erasure failed"})
		return
	case err != nil:
		// Erased durably, but anchoring the proof did not complete. Report success with the proof
		// pending; the reconciler will anchor it. Log the anchor error server-side.
		log.Printf("httpapi: erase committed but proof anchor pending (seq=%d): %v", res.Seq, err)
		writeJSON(w, http.StatusOK, map[string]any{"result": res, "proof_pending": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "proof_ref": proofRef})
}

// --- Read-only demo gateway handlers ---

func (s *Server) handleDemoMemory(w http.ResponseWriter, r *http.Request) {
	subjectID := r.URL.Query().Get("subject_id")
	if subjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	v, err := s.demo.Memory(ctx, subjectID)
	switch {
	case errors.Is(err, demo.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no memory for subject"})
	case err != nil:
		log.Printf("httpapi: demo memory failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
	default:
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *Server) handleDemoProof(w http.ResponseWriter, r *http.Request) {
	subjectID := r.URL.Query().Get("subject_id")
	if subjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	v, err := s.demo.Proof(ctx, subjectID)
	switch {
	case errors.Is(err, demo.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no erasure record for subject"})
	case err != nil:
		log.Printf("httpapi: demo proof failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
	default:
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *Server) handleDemoDecisionLog(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.demo.DecisionLog(ctx)
	if err != nil {
		log.Printf("httpapi: demo decision-log failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

func (s *Server) handleDemoVerifyChain(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := s.demo.VerifyChain(ctx)
	if err != nil {
		log.Printf("httpapi: demo verify-chain failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verification failed"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDemoRbac(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := s.demo.RbacDemo(ctx)
	if err != nil {
		log.Printf("httpapi: demo rbac probe failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "probe failed"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDemoTreeHead(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	th, err := s.demo.TreeHead(ctx)
	if err != nil {
		log.Printf("httpapi: demo tree-head failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tree head failed"})
		return
	}
	writeJSON(w, http.StatusOK, th)
}

func (s *Server) handleDemoInclusion(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
	if err != nil || seq < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "seq must be a positive integer"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	inc, err := s.demo.Inclusion(ctx, seq)
	switch {
	case errors.Is(err, demo.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no decision-log entry with that seq"})
	case err != nil:
		log.Printf("httpapi: demo inclusion failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "inclusion failed"})
	default:
		writeJSON(w, http.StatusOK, inc)
	}
}

func (s *Server) handleDemoInversion(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	v, err := s.demo.Inversion(ctx)
	if err != nil {
		log.Printf("httpapi: demo inversion failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "inversion unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}
