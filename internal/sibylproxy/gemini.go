//go:build !sibyl_stub

package sibylproxy

// gemini.go adds a Gemini backend to PickBackend.
//
// Design: GeminiClient is a plain struct whose Complete method satisfies
// agent.CompleteFunc — func(ctx, system, user) (string, error). That's it.
// No interface, no wrapper ceremony. The same Chain/WithLogging/WithRetry
// middleware that wraps the Anthropic client wraps this one identically.
// CompleteAsArrow and ArrowAsComplete from agent/lift.go handle the weft
// Arrow algebra integration automatically — nothing special needed here.
//
// Authentication follows the same env-var convention as the Anthropic
// backend: credentials in config fields take precedence; empty fields fall
// back to well-known env vars. Two modes:
//
//   Developer API  (default):  GOOGLE_API_KEY   → genai.BackendGeminiAPI
//   Vertex AI / Enterprise:    GOOGLE_CLOUD_PROJECT + GOOGLE_CLOUD_LOCATION
//                              + GOOGLE_GENAI_USE_ENTERPRISE=true
//                              → genai.BackendVertexAI

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/genai"

	"github.com/vinodhalaharvi/sibyl/agent"
)

// GeminiConfig mirrors AnthropicConfig's shape so the two backends are
// configured symmetrically. Every field has a matching env-var fallback.
type GeminiConfig struct {
	// Model is the Gemini model name. Defaults to "gemini-2.5-flash".
	Model string

	// APIKey is the Gemini Developer API key.
	// Falls back to GOOGLE_API_KEY if empty.
	APIKey string

	// UseEnterprise routes to Vertex AI / Gemini Enterprise Agent Platform.
	// Enabled automatically when GOOGLE_GENAI_USE_ENTERPRISE=true.
	UseEnterprise bool

	// Project is the GCP project ID (Vertex AI / Enterprise only).
	// Falls back to GOOGLE_CLOUD_PROJECT.
	Project string

	// Location is the GCP region (Vertex AI / Enterprise only).
	// Falls back to GOOGLE_CLOUD_LOCATION. Defaults to "us-central1".
	Location string

	// Temperature controls determinism. Defaults to 0.2 — we want
	// evidence-based judgments, not creative prose.
	Temperature float32
}

// defaultGeminiModel is used when GeminiConfig.Model is empty.
const defaultGeminiModel = "gemini-2.5-flash"

// GeminiClient wraps the Google Gen AI SDK. Its Complete method satisfies
// agent.CompleteFunc via a method value:
//
//	c, _ := NewGeminiClient(ctx, cfg)
//	var f agent.CompleteFunc = c.Complete
//
// Compose with middleware exactly as with the Anthropic backend:
//
//	complete := agent.Chain(
//	    c.Complete,
//	    agent.WithLogging(slog.Default()),
//	    agent.WithRetry(3, 200*time.Millisecond),
//	)
//
// Or lift into the weft Arrow algebra:
//
//	arrow := agent.CompleteAsArrow(c.Complete)   // Arrow[CompletionRequest, string]
//	piped := weft.Pipe3(buildReq, arrow, parse)   // Arrow[ResearchInput, Finding]
//	back  := agent.ArrowAsComplete(piped)          // CompleteFunc again
type GeminiClient struct {
	client *genai.Client
	model  string
	temp   float32
}

// NewGeminiClient validates config, resolves credentials from env vars,
// and returns a ready client. Mirrors NewAnthropicClient's error contract:
// missing credentials → error at construction, not at call time.
func NewGeminiClient(ctx context.Context, cfg GeminiConfig) (*GeminiClient, error) {
	if cfg.Model == "" {
		cfg.Model = defaultGeminiModel
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.2
	}

	useEnterprise := cfg.UseEnterprise ||
		os.Getenv("GOOGLE_GENAI_USE_ENTERPRISE") == "true"

	var clientCfg *genai.ClientConfig

	if useEnterprise {
		project := firstNonEmpty(cfg.Project, os.Getenv("GOOGLE_CLOUD_PROJECT"))
		if project == "" {
			return nil, fmt.Errorf("gemini enterprise: GOOGLE_CLOUD_PROJECT required")
		}
		location := firstNonEmpty(cfg.Location, os.Getenv("GOOGLE_CLOUD_LOCATION"), "us-central1")
		clientCfg = &genai.ClientConfig{
			Project:  project,
			Location: location,
			Backend:  genai.BackendVertexAI,
		}
	} else {
		apiKey := firstNonEmpty(cfg.APIKey, os.Getenv("GOOGLE_API_KEY"))
		if apiKey == "" {
			return nil, fmt.Errorf("gemini: GOOGLE_API_KEY required (or pass -gemini-key)")
		}
		clientCfg = &genai.ClientConfig{
			APIKey:  apiKey,
			Backend: genai.BackendGeminiAPI,
		}
	}

	client, err := genai.NewClient(ctx, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("gemini: build client: %w", err)
	}
	return &GeminiClient{client: client, model: cfg.Model, temp: cfg.Temperature}, nil
}

// Complete calls Gemini and returns the response text.
// Satisfies agent.CompleteFunc as a method value.
//
// system is passed via GenerateContentConfig.SystemInstruction — the
// dedicated Gemini 2.x field — so the model sees it as an out-of-band
// instruction, not as a user turn. This matches the Anthropic backend's
// use of the system field and keeps both backends symmetric.
func (g *GeminiClient) Complete(ctx context.Context, system, user string) (string, error) {
	cfg := &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: []*genai.Part{{Text: system}},
		},
		Temperature: genai.Ptr(g.temp),
	}

	contents := []*genai.Content{
		{Role: "user", Parts: []*genai.Part{{Text: user}}},
	}

	resp, err := g.client.Models.GenerateContent(ctx, g.model, contents, cfg)
	if err != nil {
		return "", fmt.Errorf("gemini GenerateContent: %w", err)
	}

	text := resp.Text()
	if text == "" {
		if len(resp.Candidates) > 0 {
			return "", fmt.Errorf("gemini: empty response (finish_reason=%v)",
				resp.Candidates[0].FinishReason)
		}
		return "", fmt.Errorf("gemini: empty response (no candidates)")
	}
	return text, nil
}

// firstNonEmpty returns the first non-empty string from vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// pickGemini constructs a Gemini CompleteFunc wrapped with the same
// logging + retry middleware used by every other backend. Extracted
// so PickBackend stays a clean dispatch table.
func pickGemini(ctx context.Context, model string) (agent.CompleteFunc, error) {
	c, err := NewGeminiClient(ctx, GeminiConfig{Model: model})
	if err != nil {
		return nil, err
	}
	// Wrap with standard middleware — identical composition to Anthropic.
	// Chain reads left-to-right: logging sees first, retry wraps the
	// actual network call. Temporal's activity-level retry sits outside
	// this; WithRetry absorbs brief transient errors inside one attempt.
	return agent.Chain(
		c.Complete,
		agent.WithLogging(nil),                   // nil → slog.Default()
		agent.WithRetry(3, 200*time.Millisecond), // 200ms initial backoff
	), nil
}
