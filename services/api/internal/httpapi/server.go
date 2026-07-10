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
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
)

// Server wires the store and the erasure service to HTTP handlers.
type Server struct {
	store  *store.Store
	erase  *erasure.Service
	commit string // the deployed git SHA, echoed by /healthz so we can prove what is served
}

// New builds a Server.
func New(s *store.Store, e *erasure.Service, commit string) *Server {
	return &Server{store: s, erase: e, commit: commit}
}

// Routes returns the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
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

	res, err := s.erase.Erase(ctx, req.SubjectID, erasure.ActionErasure, basis)
	switch {
	case errors.Is(err, erasure.ErrAlreadyErased):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already erased"})
		return
	case errors.Is(err, erasure.ErrSubjectNotFound):
		// A mistyped or unknown id did nothing; surface it clearly and log it so it is not mistaken
		// for a completed erasure.
		log.Printf("httpapi: erase requested for unknown subject")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown subject"})
		return
	case err != nil:
		// A real failure: log the detail server-side, return a generic error to the client so
		// internal SQL/schema structure is not disclosed.
		log.Printf("httpapi: erase failed (basis=%s): %v", basis, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "erasure failed"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}
