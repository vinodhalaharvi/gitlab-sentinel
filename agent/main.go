// Command sentinel-agent is a Google ADK (Go) agent that translates natural
// language security scan requests into calls to the gitlab-sentinel backend.
//
// Architecture (category-theoretic framing):
//
//	η: UserIntent ──▶ RunRequest ──Arrow──▶ AuditOutput
//
//	η  = this agent: the natural transformation from unstructured user intent
//	     to the typed RunRequest that SecurityAuditWorkflow expects.
//	Arrow = the full categorical composition inside gitlab-sentinel
//	        (scanners → Researcher/Critic → synthesis). Unchanged.
//
// Usage (local ADK web UI):
//
//	export GOOGLE_API_KEY=AIza...
//	export SENTINEL_URL=http://localhost:8090
//	go run github.com/vinodhalaharvi/gitlab-sentinel/agent
//
// Then open http://localhost:8080 for the ADK web UI.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/cmd/launcher"
	"google.golang.org/adk/cmd/launcher/full"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
	"google.golang.org/genai"
)

// sentinelURL is the base URL of the gitlab-sentinel backend.
var sentinelURL = strings.TrimRight(
	envOr("SENTINEL_URL", "http://localhost:8090"),
	"/",
)

// ── Tool argument / result types ──────────────────────────────────────────────

// ScanProjectArgs are the parameters for scan_project.
type ScanProjectArgs struct {
	// Project is the GitLab project path (e.g. "mygroup/myrepo") or numeric ID.
	// Leave empty to use the server's configured default project.
	Project string `json:"project"`
}

// ScanProjectResult is the result of scan_project.
type ScanProjectResult struct {
	WorkflowID string `json:"workflow_id"`
	Status     string `json:"status"`
	MonitorURL string `json:"monitor_url"`
	EventsURL  string `json:"events_url"`
	Message    string `json:"message"`
}

// AuditReportArgs are the parameters for get_audit_report.
type AuditReportArgs struct {
	// WorkflowID is the workflow_id returned by scan_project.
	WorkflowID string `json:"workflow_id"`
}

// FindingSummary is a condensed finding for the agent response.
type FindingSummary struct {
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Scanner   string `json:"scanner"`
	Rationale string `json:"rationale"`
}

// AuditReportResult is the result of get_audit_report.
type AuditReportResult struct {
	FindingsCount        int              `json:"findings_count"`
	RejectedCount        int              `json:"rejected_count"`
	FalsePositivesCaught int              `json:"false_positives_caught"`
	Findings             []FindingSummary `json:"findings"`
	MonitorURL           string           `json:"monitor_url"`
}

// HealthResult is the result of check_health.
type HealthResult struct {
	Status string `json:"status"`
	URL    string `json:"url"`
	Error  string `json:"error,omitempty"`
}

// ── Tool handlers ─────────────────────────────────────────────────────────────

// scanProject starts a security audit on a GitLab project.
// It is the entry point of the arrow composition: η maps the intent to
// a RunRequest, then POSTs to /run to start SecurityAuditWorkflow.
func scanProject(_ tool.Context, args ScanProjectArgs) (ScanProjectResult, error) {
	payload := map[string]any{}
	if args.Project != "" {
		payload["gitlab_project"] = args.Project
	}

	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		sentinelURL+"/run", strings.NewReader(string(body)))
	if err != nil {
		return ScanProjectResult{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ScanProjectResult{}, fmt.Errorf("POST /run: %w", err)
	}
	defer resp.Body.Close()

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ScanProjectResult{}, fmt.Errorf("decode response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return ScanProjectResult{}, fmt.Errorf("sentinel error %d: %v", resp.StatusCode, out)
	}

	wfID, _ := out["workflow_id"].(string)
	return ScanProjectResult{
		WorkflowID: wfID,
		Status:     "started",
		MonitorURL: sentinelURL,
		EventsURL:  sentinelURL + "/events?workflow_id=" + wfID,
		Message: fmt.Sprintf(
			"Security audit started for %q. Workflow: %s. Monitor live at: %s",
			coalesce(args.Project, "default project"), wfID, sentinelURL,
		),
	}, nil
}

// getAuditReport fetches the completed report for a finished audit.
func getAuditReport(_ tool.Context, args AuditReportArgs) (AuditReportResult, error) {
	if args.WorkflowID == "" {
		return AuditReportResult{}, fmt.Errorf("workflow_id required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := sentinelURL + "/report?workflow_id=" + args.WorkflowID
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AuditReportResult{}, fmt.Errorf("GET /report: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)

	rep := mapGet(out, "Report", "report")
	findings := sliceGet(rep, "Findings", "findings")
	rejected := sliceGet(rep, "Rejected", "rejected")

	summaries := make([]FindingSummary, 0, len(findings))
	for _, f := range findings {
		fm, _ := f.(map[string]any)
		if fm == nil {
			continue
		}
		rat, _ := strGet(fm, "LLMRationale", "llm_rationale")
		if len(rat) > 300 {
			rat = rat[:300] + "…"
		}
		title, _ := strGet(fm, "Title", "title")
		sev, _ := strGet(fm, "Severity", "severity")
		scanner, _ := strGet(fm, "ScannerID", "scanner_id")
		summaries = append(summaries, FindingSummary{
			Title:     title,
			Severity:  sev,
			Scanner:   scanner,
			Rationale: rat,
		})
	}

	return AuditReportResult{
		FindingsCount:        len(findings),
		RejectedCount:        len(rejected),
		FalsePositivesCaught: len(rejected),
		Findings:             summaries,
		MonitorURL:           sentinelURL,
	}, nil
}

// checkHealth checks that the backend is healthy.
func checkHealth(_ tool.Context, _ struct{}) (HealthResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, sentinelURL+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return HealthResult{Status: "error", URL: sentinelURL, Error: err.Error()}, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return HealthResult{Status: strings.TrimSpace(string(body)), URL: sentinelURL}, nil
}

// ── System instruction ────────────────────────────────────────────────────────

const systemInstruction = `You are GitLab Sentinel — an agentic security scanner for GitLab repositories.

Your job: help developers scan their GitLab projects for security issues,
report findings, and explain what the AI found and why.

How the backend works:
  Five parallel scanners run concurrently:
    1. GitLab scanner — code blob search + open MR diff scanning for secrets
    2. Secrets scanner — regex patterns across the local file tree
    3. OAuth scanner  — grants unused for 365+ days
    4. Scopes scanner — over-privileged OAuth clients
    5. Dormancy scanner — AWS IAM accounts with stale access keys

  Every candidate finding goes through adversarial Researcher/Critic debate:
    - Researcher: proposes finding + evidence
    - Critic: demands citations, rejects false positives (up to 3 rounds)
    - Only findings that survive reach the final report

Architecture: η: UserIntent ──▶ RunRequest ──Arrow──▶ AuditOutput
  You are η (the natural transformation). The Arrow — Temporal workflows,
  Gemini Researcher/Critic, GitLab MCP scanner — runs unchanged after /run.

Be direct and technical. Always provide the workflow_id and monitor URL.
If a CRITICAL finding is present, state the urgency clearly.`

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	ctx := context.Background()

	model, err := gemini.NewModel(ctx,
		envOr("SENTINEL_AGENT_MODEL", "gemini-2.5-flash"),
		&genai.ClientConfig{
			APIKey:  os.Getenv("GOOGLE_API_KEY"),
			Backend: genai.BackendGeminiAPI,
		})
	if err != nil {
		log.Fatalf("gemini model: %v", err)
	}

	scanTool, err := functiontool.New(functiontool.Config{
		Name: "scan_project",
		Description: `Start a security audit on a GitLab project using GitLab Sentinel.
Scans for secrets, stale OAuth, over-privileged scopes, and dormant IAM accounts.
Every finding is debated by a Researcher/Critic pair before being surfaced.
Returns workflow_id and monitor_url.`,
	}, scanProject)
	if err != nil {
		log.Fatalf("scan_project tool: %v", err)
	}

	reportTool, err := functiontool.New(functiontool.Config{
		Name: "get_audit_report",
		Description: `Fetch the completed report for a finished security audit.
Call after scan_project once the audit is complete (30–120 seconds).
Returns accepted findings with Researcher/Critic rationale and false positive count.`,
	}, getAuditReport)
	if err != nil {
		log.Fatalf("get_audit_report tool: %v", err)
	}

	healthTool, err := functiontool.New(functiontool.Config{
		Name:        "check_health",
		Description: "Check that the gitlab-sentinel backend is healthy and reachable.",
	}, checkHealth)
	if err != nil {
		log.Fatalf("check_health tool: %v", err)
	}

	a, err := llmagent.New(llmagent.Config{
		Name:        "gitlab_sentinel_agent",
		Model:       model,
		Description: "Agentic security scanner for GitLab — Google Cloud Rapid Agent Hackathon, GitLab track.",
		Instruction: systemInstruction,
		Tools:       []tool.Tool{scanTool, reportTool, healthTool},
	})
	if err != nil {
		log.Fatalf("build agent: %v", err)
	}

	log.Printf("GitLab Sentinel ADK agent starting (backend: %s)", sentinelURL)

	cfg := &launcher.Config{
		AgentLoader: agent.NewSingleLoader(a),
	}
	l := full.NewLauncher()
	if err := l.Execute(ctx, cfg, os.Args[1:]); err != nil {
		log.Fatalf("launch: %v\n\n%s", err, l.CommandLineSyntax())
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func coalesce(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

func mapGet(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if mm, ok := v.(map[string]any); ok {
				return mm
			}
		}
	}
	return nil
}

func sliceGet(m map[string]any, keys ...string) []any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.([]any); ok {
				return s
			}
		}
	}
	return nil
}

func strGet(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}
