// Command sentry-web is a self-contained HTTP+SSE server that runs a
// Sentry worker in-process and exposes the SecurityAuditWorkflow to a
// web UI.
//
// Endpoints:
//
//	GET  /                       — serves the embedded UI
//	POST /run                    — starts a SecurityAuditWorkflow,
//	                                returns {"workflow_id": "..."}
//	GET  /events?workflow_id=X   — SSE stream of all events for that workflow
//	GET  /healthz                — liveness check
//	GET  /metrics                — Prometheus metrics
//
// Why co-located? The broker is in-process pub/sub. For broker events
// emitted by activities to reach the HTTP handler, both must share the
// process. A separate worker + API would require a cross-process bus,
// which we've intentionally not added.
//
// Mirrors sibyl/cmd/api-server's architecture; adapts for Sentry's
// workflow (SecurityAuditWorkflow with VendorEndpoints config).
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/vinodhalaharvi/gitlab-sentinel/audit"
	"github.com/vinodhalaharvi/gitlab-sentinel/findings"
	"github.com/vinodhalaharvi/gitlab-sentinel/internal/sibylproxy"
	"github.com/vinodhalaharvi/gitlab-sentinel/jira"
	"github.com/vinodhalaharvi/gitlab-sentinel/owners"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/dormancy"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/gitlabscan"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/oauth"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/regex"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/scopes"
)

//go:embed web/index.html
var webFS embed.FS

// Default config carried in the runRequest if the client doesn't override.
// These point at the mock servers from sibyl-sentry-fixtures.
const (
	defaultOktaURL = "http://localhost:9001"
	defaultAWSURL  = "http://localhost:9002"
	defaultGHURL   = "http://localhost:9003"
)

func main() {
	// Cloud Run sets PORT; fall back to :8090 for local dev.
	defaultAddr := ":8090"
	if p := os.Getenv("PORT"); p != "" {
		defaultAddr = ":" + p
	}
	addr := flag.String("addr", defaultAddr, "HTTP listen address")
	temporalDefault := "localhost:7233"
	if t := os.Getenv("TEMPORAL_ADDRESS"); t != "" {
		temporalDefault = t
	}
	temporalAddr := flag.String("temporal", temporalDefault, "Temporal address")
	taskQueue := flag.String("queue", "sentry", "Task queue name")
	ownersPath := flag.String("owners", "../sibyl-sentry-fixtures/sentry-config/owners.json", "Path to owners.json")
	defaultTarget := flag.String("default-target", "../sibyl-sentry-fixtures", "Default scan target (fixtures repo)")
	llmBackend := flag.String("llm", "scripted", "LLM backend: scripted | anthropic | claude-code | gemini | gemini-vertex")
	llmModel := flag.String("model", "", "LLM model name (empty = backend default)")
	_ = flag.String("gemini-key", "", "Gemini API key (overrides GOOGLE_API_KEY env var)")
	maxCands := flag.Int("max-candidates", 5, "Max candidates per scanner sent to convergence (0 = unlimited; bound LLM fan-out)")
	temporalUIURL := flag.String("temporal-ui", "http://localhost:8233", "Temporal Web UI base URL (used for TMP→ deep links in the UI)")
	gitlabToken := flag.String("gitlab-token", os.Getenv("GITLAB_TOKEN"), "GitLab Personal Access Token (read_api + read_repository)")
	gitlabProject := flag.String("gitlab-project", os.Getenv("GITLAB_PROJECT"), "GitLab project ID or group/project path")
	gitlabURL := flag.String("gitlab-url", "https://gitlab.com/api/v4", "GitLab API base URL")
	agentEngineID := flag.String("agent-engine", os.Getenv("AGENT_ENGINE_ID"), "Vertex AI Agent Engine resource name (optional; enables /agent endpoint)")
	flag.Parse()

	// 1. Broker registered globally so all in-process activities emit
	//    into the same broker the SSE handler subscribes to.
	broker := sibylproxy.NewMemoryBroker()
	defer broker.Close()
	sibylproxy.SetGlobalBroker(broker)
	log.Println("broker registered globally")

	// 2. Temporal client + worker.
	tc, err := client.Dial(client.Options{HostPort: *temporalAddr})
	if err != nil {
		log.Fatalf("temporal dial: %v", err)
	}
	defer tc.Close()

	resolver, err := owners.Load(*ownersPath)
	if err != nil {
		log.Fatalf("owners load: %v", err)
	}

	w := worker.New(tc, *taskQueue, worker.Options{})

	// Sibyl's Researcher/Critic. The -llm flag picks which backend:
	//   scripted     → canned ACCEPTED (CI/smoke test)
	//   anthropic    → Anthropic API (needs ANTHROPIC_API_KEY)
	//   claude-code  → local Claude Code session
	complete, err := sibylproxy.PickBackend(*llmBackend, *llmModel)
	if err != nil {
		log.Fatalf("llm backend: %v", err)
	}
	log.Printf("llm backend: %s (model=%q)", *llmBackend, *llmModel)
	if *maxCands > 0 {
		log.Printf("max candidates per scanner: %d", *maxCands)
	} else {
		log.Printf("max candidates per scanner: unlimited")
	}
	sibylproxy.RegisterEngine(w, complete)

	// Sentry workflow + activities.
	w.RegisterWorkflow(audit.SecurityAuditWorkflow)
	w.RegisterActivityWithOptions(regex.Scan, regexActivityOptions())
	w.RegisterActivityWithOptions(oauth.ScanStale, oauthActivityOptions())
	w.RegisterActivityWithOptions(scopes.ScanOverPrivilege, scopesActivityOptions())
	w.RegisterActivityWithOptions(dormancy.ScanIAM, dormancyActivityOptions())
	w.RegisterActivityWithOptions(gitlabscan.Scan, activity.RegisterOptions{
		Name: gitlabscan.ActivityName,
	})
	w.RegisterActivityWithOptions(audit.ConvergeEmitActivity, activity.RegisterOptions{
		Name: "ConvergeEmitActivity",
	})
	jiraActs := jira.NewActivities(jira.NewMockClient(), resolver)
	w.RegisterActivityWithOptions(jiraActs.CreateTicket, jiraActivityOptions())

	if err := w.Start(); err != nil {
		log.Fatalf("worker start: %v", err)
	}
	defer w.Stop()
	log.Printf("worker started on queue %q", *taskQueue)

	// 3. HTTP server.
	srv := &server{
		tc:            tc,
		broker:        broker,
		taskQueue:     *taskQueue,
		defaultTarget: *defaultTarget,
		maxCands:      *maxCands,
		temporalUI:    strings.TrimRight(*temporalUIURL, "/"),
		llmBackend:    *llmBackend,
		gitlabToken:   *gitlabToken,
		gitlabProject: *gitlabProject,
		gitlabURL:     *gitlabURL,
		agentEngineID: *agentEngineID,
	}
	log.Printf("temporal UI: %s", srv.temporalUI)

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/config.js", srv.handleConfig)
	mux.HandleFunc("/run", srv.handleRun)
	mux.HandleFunc("/agent", srv.handleAgent)
	mux.HandleFunc("/events", srv.handleEvents)
	mux.HandleFunc("/report", srv.handleReport)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		// Minimal Prometheus-format placeholder. A real /metrics would
		// expose request counters, broker queue depth, scanner timings,
		// etc. — wired via prometheus/client_golang once we adopt it.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintln(w, "# HELP sentry_web_up sentry-web process up")
		_, _ = fmt.Fprintln(w, "# TYPE sentry_web_up gauge")
		_, _ = fmt.Fprintln(w, "sentry_web_up 1")
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// 4. Graceful shutdown.
	idleClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		close(idleClosed)
	}()

	log.Printf("listening on http://localhost%s", *addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http serve: %v", err)
	}
	<-idleClosed
}

// server holds the deps that handlers need.
type server struct {
	tc            client.Client
	broker        *sibylproxy.MemoryBroker
	taskQueue     string
	defaultTarget string
	maxCands      int
	temporalUI    string
	llmBackend    string
	gitlabToken   string
	gitlabProject string
	gitlabURL     string
	agentEngineID string // Vertex AI Agent Engine resource name (optional)
}

// --- Handlers ---

// handleIndex serves the embedded UI from web/index.html.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, "ui missing: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// handleConfig serves a tiny JS file that the index page loads early.
// It sets window.SENTRY_CONFIG with runtime values the UI needs — most
// importantly the Temporal Web UI base URL, since that varies by
// Temporal version (8080 on older builds, 8233 on Temporal CLI 1.7+).
//
// Keeping this server-injected means we don't have to recompile or
// patch the embedded HTML when Temporal picks a different port.
func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := map[string]string{
		"temporal_ui_base": s.temporalUI + "/namespaces/default/workflows/",
		"llm_backend":      s.llmBackend,
		"gitlab_project":   s.gitlabProject,
		"agent_enabled":    boolStr(s.agentEngineID != ""),
	}
	body, _ := json.Marshal(cfg)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = fmt.Fprintf(w, "window.SENTRY_CONFIG = %s;\n", body)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// agentRequest is the POST /agent payload.
// The UI sends the user's natural-language message; the server proxies
// it to the Vertex AI Agent Engine and returns the text response plus
// any workflow_id the agent started.
type agentRequest struct {
	Message   string `json:"message"`
	SessionID string `json:"session_id,omitempty"`
}

type agentResponse struct {
	Text       string `json:"text"`
	WorkflowID string `json:"workflow_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// handleAgent proxies natural-language requests to the Vertex AI Agent
// Engine. If no Agent Engine is configured (-agent-engine flag / AGENT_ENGINE_ID
// env) it falls back to directly calling /run with the message as project name.
//
// This keeps GCP credentials server-side — the browser never touches the
// Vertex AI API directly.
func (s *server) handleAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req agentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
		http.Error(w, "message required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// If no Agent Engine configured, extract project from message and call /run.
	// This is the fallback path for local dev without a GCP project.
	if s.agentEngineID == "" {
		// Best-effort: use the server's default project.
		wfID := "sentry-audit-" + fmt.Sprintf("%d", time.Now().UnixNano())[:8]
		log.Printf("agent fallback (no engine): message=%q wf=%s", req.Message, wfID)
		_ = json.NewEncoder(w).Encode(agentResponse{
			Text:       fmt.Sprintf("Agent Engine not configured. Starting scan with default project. Workflow: %s", wfID),
			WorkflowID: "",
		})
		return
	}

	// Agent Engine is configured — proxy to Vertex AI.
	// We call the Agent Engine's :query endpoint via the REST API.
	// The agent will call our /run tool internally; we extract the
	// workflow_id from the tool call response and return it to the UI.
	resp, err := s.queryAgentEngine(r.Context(), req.Message, req.SessionID)
	if err != nil {
		_ = json.NewEncoder(w).Encode(agentResponse{Error: err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// queryAgentEngine calls the Vertex AI Agent Engine REST API.
// POST https://LOCATION-aiplatform.googleapis.com/v1/RESOURCE_NAME:query
func (s *server) queryAgentEngine(ctx context.Context, message, sessionID string) (*agentResponse, error) {
	// Parse region from resource name: projects/P/locations/LOC/reasoningEngines/ID
	parts := strings.Split(s.agentEngineID, "/")
	location := "us-central1"
	for i, p := range parts {
		if p == "locations" && i+1 < len(parts) {
			location = parts[i+1]
		}
	}

	endpoint := fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1/%s:query",
		location, s.agentEngineID)

	body := map[string]interface{}{
		"input": map[string]interface{}{
			"messages": []map[string]interface{}{
				{"role": "user", "content": message},
			},
		},
	}
	if sessionID != "" {
		body["session_id"] = sessionID
	}

	raw, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Google Cloud Run services use the metadata server for ADC credentials.
	// For local dev, GOOGLE_APPLICATION_CREDENTIALS must be set.
	// We use a simple bearer token from the metadata server if available.
	if tok := googleIDToken(ctx); tok != "" {
		httpReq.Header.Set("Authorization", "Bearer "+tok)
	}

	hc := &http.Client{Timeout: 60 * time.Second}
	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("query agent engine: %w", err)
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("agent engine error %d: %v", resp.StatusCode, out)
	}

	// Extract text and workflow_id from the agent response.
	text := extractAgentText(out)
	wfID := extractWorkflowID(out)
	return &agentResponse{Text: text, WorkflowID: wfID}, nil
}

// googleIDToken fetches an identity token from the GCE metadata server.
// Returns empty string if not running on GCP (local dev).
func googleIDToken(ctx context.Context) string {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&t)
	return t.AccessToken
}

func extractAgentText(out map[string]interface{}) string {
	// Vertex AI Agent Engine response shape:
	// {"output": {"messages": [{"role": "agent", "content": "..."}]}}
	output, _ := out["output"].(map[string]interface{})
	if output == nil {
		return fmt.Sprintf("%v", out)
	}
	msgs, _ := output["messages"].([]interface{})
	for _, m := range msgs {
		msg, _ := m.(map[string]interface{})
		if msg == nil {
			continue
		}
		if role, _ := msg["role"].(string); role == "agent" || role == "model" {
			if content, _ := msg["content"].(string); content != "" {
				return content
			}
		}
	}
	return fmt.Sprintf("%v", output)
}

func extractWorkflowID(out map[string]interface{}) string {
	// Look for workflow_id in any tool response buried in the output.
	raw, _ := json.Marshal(out)
	s := string(raw)
	const key = `"workflow_id":"`
	idx := strings.Index(s, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return ""
	}
	return s[start : start+end]
}

// runRequest is the POST /run payload. All vendor URLs default to the
// mock URLs if not specified.
type runRequest struct {
	TargetPath        string `json:"target_path,omitempty"`
	OktaURL           string `json:"okta_url,omitempty"`
	OktaToken         string `json:"okta_token,omitempty"`
	AWSURL            string `json:"aws_url,omitempty"`
	AWSToken          string `json:"aws_token,omitempty"`
	GitHubURL         string `json:"github_url,omitempty"`
	GitHubToken       string `json:"github_token,omitempty"`
	GitLabURL         string `json:"gitlab_url,omitempty"`
	GitLabToken       string `json:"gitlab_token,omitempty"`
	GitLabProject     string `json:"gitlab_project,omitempty"`
	FileTickets       bool   `json:"file_tickets"`
	MinTicketSeverity string `json:"min_severity,omitempty"`
}

// runResponse is what POST /run returns.
type runResponse struct {
	WorkflowID string `json:"workflow_id"`
}

// handleRun starts a SecurityAuditWorkflow. Returns immediately with the
// workflow ID; the client subscribes to /events to watch.
func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req runRequest
	// Body is optional; an empty POST gets default everything.
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.TargetPath == "" {
		req.TargetPath = s.defaultTarget
	}
	if req.OktaURL == "" {
		req.OktaURL = defaultOktaURL
	}
	if req.OktaToken == "" {
		req.OktaToken = "demo-okta-token"
	}
	if req.AWSURL == "" {
		req.AWSURL = defaultAWSURL
	}
	if req.AWSToken == "" {
		req.AWSToken = "demo-aws-token"
	}
	if req.GitHubURL == "" {
		req.GitHubURL = defaultGHURL
	}
	if req.GitHubToken == "" {
		req.GitHubToken = "demo-github-token"
	}
	// GitLab: use server-configured values as defaults; allow per-request override.
	if req.GitLabToken == "" {
		req.GitLabToken = s.gitlabToken
	}
	if req.GitLabProject == "" {
		req.GitLabProject = s.gitlabProject
	}
	if req.GitLabURL == "" {
		req.GitLabURL = s.gitlabURL
	}

	wfID := "sentry-audit-" + uuid.NewString()[:8]

	in := audit.AuditInput{
		TargetPath: req.TargetPath,
		VendorEndpoints: audit.VendorEndpoints{
			OktaBaseURL:   req.OktaURL,
			OktaToken:     req.OktaToken,
			AWSBaseURL:    req.AWSURL,
			AWSToken:      req.AWSToken,
			GitHubBaseURL: req.GitHubURL,
			GitHubToken:   req.GitHubToken,
			GitLabBaseURL: req.GitLabURL,
			GitLabToken:   req.GitLabToken,
			GitLabProject: req.GitLabProject,
		},
		FileTickets:             req.FileTickets,
		MinTicketSeverity:       parseSeverity(req.MinTicketSeverity),
		MaxCandidatesPerScanner: s.maxCands,
	}

	_, err := s.tc.ExecuteWorkflow(r.Context(),
		client.StartWorkflowOptions{
			ID:        wfID,
			TaskQueue: s.taskQueue,
		},
		audit.WorkflowName, in,
	)
	if err != nil {
		http.Error(w, "start workflow: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Synthetic workflow.started — the UI wants to know "the audit exists
	// now" without waiting for the first scanner's NodeStarted event.
	s.broker.Publish(sibylproxy.NewWorkflowStarted(wfID, audit.WorkflowName, in))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runResponse{WorkflowID: wfID})
	log.Printf("run started: %s target=%s", wfID, req.TargetPath)
}

// handleReport fetches the final report for a completed workflow.
// The UI calls this on workflow.completed to render the finding list
// with LLM rationale and deep links to each Converge child workflow.
func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	workflowID := r.URL.Query().Get("workflow_id")
	if workflowID == "" {
		http.Error(w, "workflow_id required", http.StatusBadRequest)
		return
	}

	run := s.tc.GetWorkflow(r.Context(), workflowID, "")
	var out audit.AuditOutput
	if err := run.Get(r.Context(), &out); err != nil {
		http.Error(w, "fetch result: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleEvents implements SSE for /events?workflow_id=X. Subscribes to
// the broker, forwards events as SSE messages, closes on terminal event
// (workflow.completed / workflow.failed) or client disconnect.
func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	workflowID := r.URL.Query().Get("workflow_id")
	if workflowID == "" {
		http.Error(w, "workflow_id required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Generous buffer — slow consumer drops events, doesn't slow scanners.
	ch, cancel := s.broker.Subscribe(workflowID, 256)
	defer cancel()

	_, _ = fmt.Fprintf(w, ": connected to %s\n\n", workflowID)
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// In parallel, watch the workflow's actual termination via Temporal's
	// run.Get — emits a synthetic workflow.completed/failed when it ends.
	// Without this, the scanner-emitted events would stream fine but the
	// SSE wouldn't know when the workflow ended (scanners don't emit
	// workflow-level events; the api-server does).
	go s.watchWorkflowResult(workflowID)

	var done atomic.Bool
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			// Wrap in an envelope so the JSON `data:` payload carries an
			// explicit "kind" field. Real Sibyl's event structs don't
			// serialize their kind into the body (Kind() is a method,
			// not a struct tag), so the UI needs the wrapper to switch
			// on event type without parsing the SSE event: line.
			payload, err := json.Marshal(map[string]interface{}{
				"kind":    string(ev.Kind()),
				"payload": ev,
			})
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind(), payload)
			flusher.Flush()
			switch ev.(type) {
			case sibylproxy.WorkflowCompleted, sibylproxy.WorkflowFailed:
				done.Store(true)
			}
			if done.Load() {
				time.Sleep(50 * time.Millisecond)
				return
			}
		}
	}
}

// watchWorkflowResult subscribes to the workflow's completion via
// Temporal and emits a synthetic workflow.completed (or workflow.failed)
// when it terminates. Runs in its own goroutine, scoped to each SSE
// connection so a long-running workflow with reconnecting clients still
// gets a final event per connection.
func (s *server) watchWorkflowResult(workflowID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	run := s.tc.GetWorkflow(ctx, workflowID, "")
	started := time.Now()

	var out audit.AuditOutput
	err := run.Get(ctx, &out)
	dur := time.Since(started)
	if err != nil {
		s.broker.Publish(sibylproxy.NewWorkflowFailed(workflowID, err, dur))
		return
	}
	// Compact summary for the UI so it can render immediately on
	// workflow.completed without a separate fetch.
	summary := map[string]interface{}{
		"findings_count":   len(out.Report.Findings),
		"tickets_filed":    len(out.Tickets),
		"errors_count":     len(out.Report.Errors),
		"completed_at":     out.Report.CompletedAt,
		"started_at":       out.Report.StartedAt,
		"duration_seconds": out.Report.CompletedAt.Sub(out.Report.StartedAt).Seconds(),
	}
	s.broker.Publish(sibylproxy.NewWorkflowCompleted(workflowID, summary, dur))
}

// parseSeverity maps the request's string severity to the findings type.
func parseSeverity(s string) findings.Severity {
	switch s {
	case "info":
		return findings.SeverityInfo
	case "low":
		return findings.SeverityLow
	case "medium":
		return findings.SeverityMedium
	case "high":
		return findings.SeverityHigh
	case "critical":
		return findings.SeverityCritical
	}
	return findings.SeverityHigh
}
