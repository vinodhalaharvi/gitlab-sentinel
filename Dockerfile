# syntax=docker/dockerfile:1

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

WORKDIR /src

# Cache deps before copying source (layer cache friendly)
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go \
    --mount=type=cache,target=/go/pkg/mod \
    GONOSUMCHECK='*' GOFLAGS='-mod=mod' go mod download

# Copy source and build
COPY . .
RUN --mount=type=cache,target=/root/.cache/go \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    GONOSUMCHECK='*' GOFLAGS='-mod=mod' \
    go build -trimpath -ldflags="-s -w" \
    -o /out/sentry-web ./cmd/sentry-web

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/sentry-web /sentry-web

# Cloud Run sets PORT; sentry-web reads it automatically.
# All other config is via environment variables:
#
#   Required:
#     GITLAB_TOKEN          GitLab PAT (read_api + read_repository)
#     GITLAB_PROJECT        project ID or group/project path
#     TEMPORAL_ADDRESS      Temporal server address (default: localhost:7233)
#
#   LLM backend (pick one):
#     GOOGLE_API_KEY        → -llm gemini (Gemini Developer API)
#     GOOGLE_CLOUD_PROJECT  → -llm gemini-vertex (Vertex AI)
#     ANTHROPIC_API_KEY     → -llm anthropic
#
#   Optional:
#     LLM_BACKEND           overrides the -llm flag (default: gemini)
#     LLM_MODEL             overrides -model flag
#
EXPOSE 8080

ENTRYPOINT ["/sentry-web"]
