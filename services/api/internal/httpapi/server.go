// Package httpapi exposes the erasure orchestrator over HTTP.
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/demo"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/ingest"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	"github.com/StephenSook/erasure-proof/services/api/internal/stream"
)

// Server wires the store, the ingest path, the erasure orchestrator, and the read-only demo gateway
// to HTTP handlers.
type Server struct {
	store     *store.Store
	orch      *erasure.Orchestrator
	ingester  *ingest.Ingester
	demo      *demo.Service
	commit    string // the deployed git SHA, echoed by /healthz so we can prove what is served
	streamHub *stream.Hub
}

// New builds a Server.
func New(s *store.Store, orch *erasure.Orchestrator, ingester *ingest.Ingester, dsvc *demo.Service, commit string) *Server {
	return &Server{store: s, orch: orch, ingester: ingester, demo: dsvc, commit: commit}
}

// SetStreamHub wires the live decision-log changefeed feed for the SSE endpoint. Called at boot when
// the changefeed consumer is started; leaving it unset makes /api/erasure-stream serve only the
// current snapshot (no live updates).
func (s *Server) SetStreamHub(h *stream.Hub) { s.streamHub = h }

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
	mux.HandleFunc("GET /api/inversion/config", s.handleDemoInversionConfig)
	mux.HandleFunc("POST /api/inversion/live", s.handleDemoInversionLive)
	mux.HandleFunc("GET /api/inversion/live/status", s.handleDemoInversionLiveStatus)
	mux.HandleFunc("POST /api/verify-chain", s.handleDemoVerifyChain)
	mux.HandleFunc("POST /api/rbac-demo", s.handleDemoRbac)
	mux.HandleFunc("GET /api/tree-head", s.handleDemoTreeHead)
	mux.HandleFunc("GET /api/inclusion", s.handleDemoInclusion)
	mux.HandleFunc("GET /api/consistency", s.handleDemoConsistency)
	mux.HandleFunc("GET /api/erasure-stream", s.handleErasureStream)
	mux.HandleFunc("GET /api/agent/config", s.handleAgentConfig)
	mux.HandleFunc("GET /api/agent/warm", s.handleAgentWarm)
	mux.HandleFunc("POST /api/agent/forensics", s.handleAgentForensics)
	mux.HandleFunc("POST /api/agent/memory-writer", s.handleAgentMemoryWriter)
	mux.HandleFunc("POST /api/embedding/titan", s.handleTitanEmbed)
	mux.HandleFunc("POST /api/memory/search", s.handleMemorySearch)
	mux.HandleFunc("POST /api/demo/time-travel", s.handleTimeTravel)
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
	// Optional size: prove inclusion within the FIRST size leaves (the tree a signed proof
	// committed to), not the current head. 0/absent means the current tree.
	size := 0
	if v := r.URL.Query().Get("size"); v != "" {
		if size, err = strconv.Atoi(v); err != nil || size < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "size must be a positive integer"})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	inc, err := s.demo.Inclusion(ctx, seq, size)
	switch {
	case errors.Is(err, demo.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no decision-log entry with that seq in that tree"})
	case err != nil:
		log.Printf("httpapi: demo inclusion failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "inclusion failed"})
	default:
		writeJSON(w, http.StatusOK, inc)
	}
}

func (s *Server) handleDemoConsistency(w http.ResponseWriter, r *http.Request) {
	from, err := strconv.Atoi(r.URL.Query().Get("from"))
	if err != nil || from < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from must be a positive integer"})
		return
	}
	to := 0 // 0 means the current tree size
	if v := r.URL.Query().Get("to"); v != "" {
		if to, err = strconv.Atoi(v); err != nil || to < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to must be a positive integer"})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cons, err := s.demo.Consistency(ctx, from, to)
	switch {
	case errors.Is(err, demo.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid tree sizes for a consistency proof"})
	case err != nil:
		log.Printf("httpapi: demo consistency failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "consistency failed"})
	default:
		writeJSON(w, http.StatusOK, cons)
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

func (s *Server) handleDemoInversionConfig(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	v, err := s.demo.InversionConfig(ctx)
	if err != nil {
		// A config probe failure is not fatal to the page; report live unavailable and move on. Log
		// it so an outage (cryptod down) is distinguishable from an intentionally unwired deploy.
		log.Printf("demo inversion config probe failed: %v", err)
		writeJSON(w, http.StatusOK, map[string]any{"live_available": false})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleDemoInversionLive STARTS the background live inversion and returns immediately. A live GPU
// run is 1 to 2.5 minutes (cold start plus the run), longer than CloudFront's 60s origin read
// ceiling, so the old synchronous response 504'd at the edge before the origin could answer. The
// browser polls /api/inversion/live/status; every request stays short.
func (s *Server) handleDemoInversionLive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Embedding string `json:"embedding"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	job, err := s.demo.StartLiveInversion(req.Embedding)
	if errors.Is(err, demo.ErrLiveInversionBusy) {
		// A different embedding's run is in flight; refusing (the old sync path's wording) beats
		// silently answering this subject's poll with another subject's inversion.
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "the GPU is busy with another live inversion; try again in a moment",
		})
		return
	}
	if err != nil {
		// A start-time validation error (bad payload); GPU-side failures ride the status poll.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// The ?job= parameter is the id returned by the start call. Presenting it means a caller can only
// be handed the result of the run it actually started; omitting it keeps the endpoint usable by
// hand (curl) and returns whatever job is current.
func (s *Server) handleDemoInversionLiveStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.demo.LiveInversionStatus(r.URL.Query().Get("job")))
}

// handleErasureStream is a Server-Sent Events endpoint: it sends the current decision log as a
// "snapshot" event, then streams each newly appended row as a "row" event, fed by the CockroachDB
// changefeed. A ":keepalive" comment every 25s keeps proxies from timing the connection out. The
// changefeed carries no personal data (subject_hash is a SHA-256).
func (s *Server) handleErasureStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable proxy buffering (nginx/ALB) so events flush immediately.
	w.Header().Set("X-Accel-Buffering", "no")

	ctx := r.Context()
	rc := http.NewResponseController(w)

	if s.streamHub == nil {
		// No changefeed wired: send the current snapshot and close cleanly.
		rows := s.snapshotRows(ctx)
		writeSSE(w, "snapshot", map[string]any{"rows": rows, "live": false})
		flusher.Flush()
		return
	}

	// Subscribe BEFORE snapshotting, so a row appended during the snapshot read is buffered and
	// still delivered live (the client dedupes by seq). This closes the subscribe-after-snapshot
	// miss window.
	ch, unsubscribe, ok := s.streamHub.Subscribe()
	if !ok {
		rows := s.snapshotRows(ctx)
		writeSSE(w, "snapshot", map[string]any{"rows": rows, "live": false})
		writeSSE(w, "error", map[string]string{"error": "too many live viewers; showing the snapshot only"})
		flusher.Flush()
		return
	}
	defer unsubscribe()

	writeSSE(w, "snapshot", map[string]any{"rows": s.snapshotRows(ctx), "live": true})
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			writeSSE(w, "row", ev)
			flusher.Flush()
		case <-keepalive.C:
			// A short write deadline turns a half-open connection (no FIN, e.g. a closed laptop
			// lid) into a prompt write error so the subscriber slot is freed within seconds rather
			// than after TCP's multi-minute timeout.
			_ = rc.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := w.Write([]byte(":keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
			_ = rc.SetWriteDeadline(time.Time{})
		}
	}
}

// snapshotRows fetches the current decision log for the SSE snapshot, bounded by a short timeout.
func (s *Server) snapshotRows(ctx context.Context) []demo.DecisionRow {
	snapCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := s.demo.DecisionLog(snapCtx)
	if err != nil {
		log.Printf("httpapi: stream snapshot failed: %v", err)
		return nil
	}
	return rows
}

// writeSSE writes one named Server-Sent Event with a JSON data payload.
func writeSSE(w http.ResponseWriter, event string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	// The status line was already sent; a write error means the client left, which the caller's
	// next Write/Flush will also surface.
	_, _ = w.Write([]byte("event: " + event + "\ndata: "))
	_, _ = w.Write(payload)
	_, _ = w.Write([]byte("\n\n"))
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	forensics := s.demo.ForensicsAvailable()
	// The memory-writer needs Bedrock (distil) AND the embedding worker; probe the latter only when
	// Bedrock is wired, to avoid a needless cryptod call in the common unwired case.
	memWriter := forensics && s.demo.EmbedAvailable(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"live_available":          forensics,
		"forensics_available":     forensics,
		"memory_writer_available": memWriter,
		"titan_available":         s.demo.TitanAvailable(),
		"provider":                s.demo.ForensicsProvider(),
	})
}

// handleAgentWarm reports whether the live agent's model is ready, kicking a background warm on a
// cold miss; the UI polls it and holds the run button until warm, so the actual audit request
// always fits inside CloudFront's origin timeout.
func (s *Server) handleAgentWarm(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]any{"warm": s.demo.WarmForensics(ctx)})
}

func (s *Server) handleTimeTravel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	view, err := s.demo.TimeTravel(ctx)
	if err != nil {
		log.Printf("httpapi: time-travel beat failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "time-travel demo failed"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleMemorySearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectID string `json:"subject_id"`
		Embedding string `json:"embedding"` // base64 little-endian float32, the ingest wire format
		K         int    `json:"k"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil ||
		req.SubjectID == "" || req.Embedding == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id and embedding are required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	view, err := s.demo.Search(ctx, req.SubjectID, req.Embedding, req.K)
	if errors.Is(err, ingest.ErrBadEmbedding) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		log.Printf("httpapi: vector search failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vector search failed"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleTitanEmbed(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "text is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	emb, err := s.demo.TitanEmbed(ctx, req.Text)
	if errors.Is(err, demo.ErrTitanUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "titan embedding not wired"})
		return
	}
	if errors.Is(err, demo.ErrForensicsBusy) || errors.Is(err, demo.ErrForensicsBudget) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "the agent is busy or over budget; try again shortly"})
		return
	}
	if err != nil {
		log.Printf("httpapi: titan embed failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "titan embedding failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"source":            "live_bedrock_titan",
		"model_id":          emb.ModelID,
		"dimensions":        emb.Dimensions,
		"embedding_b64":     emb.EmbeddingB64,
		"sha256":            emb.Sha256,
		"input_token_count": emb.TokenCount,
	})
}

func (s *Server) handleAgentMemoryWriter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Turn string `json:"turn"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || strings.TrimSpace(req.Turn) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a conversation turn is required"})
		return
	}
	// Distil (Bedrock) + embed (cold GPU) can each take a while; order the deadlines like the
	// inversion path so the innermost layer finishes first: Modal 300 < cryptod 320 < HTTP 330 <
	// this handler 340, and the ingest that follows is quick.
	ctx, cancel := context.WithTimeout(r.Context(), 340*time.Second)
	defer cancel()

	fact, embeddingB64, err := s.demo.DistillAndEmbed(ctx, req.Turn)
	if errors.Is(err, demo.ErrMemoryWriterUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "memory writer not wired"})
		return
	}
	if errors.Is(err, demo.ErrForensicsBusy) || errors.Is(err, demo.ErrForensicsBudget) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "the agent is busy or over budget; try again shortly"})
		return
	}
	if err != nil {
		log.Printf("httpapi: memory writer distil/embed failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "memory writer failed"})
		return
	}

	// Store the agent-written memory through the normal ingest path (new subject).
	res, err := s.ingester.Ingest(ctx, "", base64.StdEncoding.EncodeToString([]byte(fact)), embeddingB64)
	if err != nil {
		log.Printf("httpapi: memory writer ingest failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "storing the memory failed"})
		return
	}
	// Return the embedding + its hash so the live-inversion beat can invert THIS memory's vector
	// (the judge's own words) and the match-check compares against the right hash. It is the
	// judge's own data returned to the same browser that typed it, not a leak of another subject.
	embHashHex := ""
	if raw, decErr := base64.StdEncoding.DecodeString(embeddingB64); decErr == nil {
		sum := sha256.Sum256(raw)
		embHashHex = hex.EncodeToString(sum[:])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"source":           "live_bedrock",
		"memory_text":      fact,
		"subject_id":       res.SubjectID,
		"memory_id":        res.MemoryID,
		"embedding_b64":    embeddingB64,
		"embedding_sha256": embHashHex,
	})
}

func (s *Server) handleAgentForensics(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectID string `json:"subject_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.SubjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id is required"})
		return
	}
	// The tool-use loop makes several Bedrock calls; give it a generous budget but bounded.
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	res, err := s.demo.ForensicsAudit(ctx, req.SubjectID)
	if errors.Is(err, demo.ErrForensicsUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "forensics agent not wired"})
		return
	}
	if errors.Is(err, demo.ErrForensicsBusy) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "the forensics agent is already running an audit; try again in a moment",
		})
		return
	}
	if errors.Is(err, demo.ErrForensicsBudget) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "the forensics-audit hourly budget is used up; try again later",
		})
		return
	}
	if err != nil {
		log.Printf("httpapi: forensics audit failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "forensics audit failed"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}
