# GitLab Sentinel — ADK Agent (Go)

Natural language interface to the gitlab-sentinel backend,
built with [Google ADK Go](https://google.golang.org/adk) v1.4.0.

## Architecture

```
η: UserIntent ──▶ RunRequest ──Arrow──▶ AuditOutput
```

This agent is **η** — the natural transformation from unstructured user intent
to the typed `RunRequest` that `SecurityAuditWorkflow` expects.
The full arrow composition (GitLab scanner → Researcher/Critic → synthesis)
runs unchanged inside the backend after `/run` is called.

## Tools

| Tool | What it does |
|------|-------------|
| `scan_project(project)` | `POST /run` → starts `SecurityAuditWorkflow` |
| `get_audit_report(workflow_id)` | `GET /report` → accepted findings + false positives |
| `check_health()` | `GET /healthz` → backend liveness |

## Run locally

```sh
export GOOGLE_API_KEY=AIza...
export SENTINEL_URL=http://localhost:8090   # or your Cloud Run URL

cd agent
go run . serve                              # ADK web UI on :8080
go run . run --query "scan mygroup/myrepo"  # one-shot console
```

## Deploy to Vertex AI Agent Engine

```sh
# Install ADK CLI
go install google.golang.org/adk/cmd/adkgo@latest

# Deploy
SENTINEL_URL=https://your-cloudrun-url adkgo deploy \
  --display-name "GitLab Sentinel" \
  --project $GOOGLE_CLOUD_PROJECT \
  --region us-central1 \
  .
```
