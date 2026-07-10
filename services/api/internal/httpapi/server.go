// Package httpapi exposes the erasure orchestrator over HTTP.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/ingest"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
)

// Server wires the store, the ingest path, and the erasure orchestrator to HTTP handlers.
type Server struct {
	store    *store.Store
	orch     *erasure.Orchestrator
	ingester *ingest.Ingester
	commit   string // the deployed git SHA, echoed by /healthz so we can prove what is served
}

// New builds a Server.
func New(s *store.Store, orch *erasure.Orchestrator, ingester *ingest.Ingester, commit string) *Server {
	return &Server{store: s, orch: orch, ingester: ingester, commit: commit}
}

// Routes returns the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /memories", s.handleIngest)
	mux.HandleFunc("POST /erase", s.handleErase)
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
	case errors.Is(err, ingest.ErrBadEmbedding), errors.Is(err, ingest.ErrBadContent):
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
