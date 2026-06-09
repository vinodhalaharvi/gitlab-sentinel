# gitlab-sentinel

> **Agentic security auditing for GitLab — powered by durable Temporal workflows and an adversarial Researcher/Critic agent loop.**
>
> Submission for the [Google Cloud Rapid Agent Hackathon](https://googlecloudrapidagenthackathon.devpost.com/) — **GitLab track**.

[![CI](https://github.com/vinodhalaharvi/gitlab-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/vinodhalaharvi/gitlab-sentinel/actions/workflows/ci.yml)

---

## What it does

GitLab Sentinel scans your GitLab projects for security issues and puts every
finding through an adversarial **Researcher / Critic** agent debate before
surfacing it to you. No hallucinated alerts. No noise.

**Five scanners run in parallel:**

| Scanner | What it finds |
|---------|--------------|
| `gitlab` | Secrets in repo blobs + open MR diffs via GitLab code search API |
| `regex` | Secrets in local working tree + full git history |
| `oauth` | Stale OAuth grants unused for 365+ days |
| `scopes` | Over-privileged OAuth clients with unused permission scopes |
| `dormancy` | Dormant AWS IAM service accounts with active keys |

**Every candidate finding goes through a convergence loop:**

```
Scanner emits candidate (evidence only, no judgment)
        ↓
Researcher agent  →  proposes DECISION + SEVERITY + RATIONALE
        ↓
Critic agent      →  demands cited evidence; approves or rejects
        ↓  (up to 3 rounds)
Accepted finding  →  LLM-justified, evidence-backed, ready for action
```

Each convergence loop is a **durable Temporal child workflow** — replayable,
resumable, and fully auditable months later. If a worker crashes mid-audit,
Temporal resumes from the exact step. If the LLM rate-limits, it waits and
retries.

---

## Architecture

```
SecurityAuditWorkflow                    ← durable parent (Temporal)
├── Scanner fan-out (parallel activities)
│     ├── gitlab.Scan    ← GitLab blob search + MR diff scan  ← GitLab MCP superpower
│     ├── regex.Scan     ← local filesystem + git history
│     ├── oauth.Scan     ← stale OAuth grants
│     ├── scopes.Scan    ← over-privileged scopes
│     └── dormancy.Scan  ← dormant IAM accounts
│
└── Convergence fan-out (one child workflow per candidate)
      ConvergeWorkflow
        ├── ResearcherActivity   ← LLM: propose finding + evidence
        └── CriticActivity       ← LLM: demand citations, accept or reject
        (up to 3 rounds)
```

**GitLab as the MCP superpower.** The `gitlab` scanner calls the same endpoints
exposed by the [official GitLab MCP server](https://docs.gitlab.com/user/gitlab_duo/model_context_protocol/):

| GitLab API endpoint | Used for |
|---------------------|---------|
| `GET /projects/:id/search?scope=blobs` | Semantic code search for 7 secret patterns |
| `GET /projects/:id/merge_requests/:iid/diffs` | Scan in-flight MR changes before merge |
| `POST /projects/:id/issues` | File security issues for accepted findings |

Secret patterns searched: AWS access keys, GitLab PATs, GitHub PATs, RSA private keys,
Anthropic API keys, Slack tokens, Google API keys.

---

## Prerequisites

- **Go 1.24+** — `go version`
- **Temporal CLI** — `brew install temporal` or [docs.temporal.io/cli](https://docs.temporal.io/cli)
- **GitLab PAT** — Personal Access Token with `read_api` + `read_repository` scopes
- **Anthropic API key** — for the Researcher/Critic agent loop
- **[sibyl-sentry-fixtures](https://github.com/vinodhalaharvi/sibyl-sentry-fixtures)** — mock Okta + AWS servers for the non-GitLab scanners

---

## Quick start — four terminals

### Terminal 1 — clone

```sh
mkdir -p ~/go-projects && cd ~/go-projects
git clone https://github.com/vinodhalaharvi/gitlab-sentinel.git
git clone https://github.com/vinodhalaharvi/sibyl-sentry-fixtures.git
```

### Terminal 2 — mock vendor servers (Okta + AWS)

```sh
cd ~/go-projects/sibyl-sentry-fixtures
make mocks-up   # starts mock-okta :9001 and mock-aws :9002
make check      # verify all healthy
```

### Terminal 3 — Temporal

```sh
temporal server start-dev
# Web UI at http://localhost:8233
```

### Terminal 4 — Sentinel

```sh
cd ~/go-projects/gitlab-sentinel
go mod tidy && go build ./...

export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
export GITLAB_PROJECT=your-group/your-project
export ANTHROPIC_API_KEY=sk-ant-...

go run ./cmd/sentry-web -llm anthropic
# UI at http://localhost:8090
```

Click **Run Audit**. The GitLab scanner searches your live project for secrets
while the other scanners hit the mock servers. Every candidate finding goes
through the Researcher/Critic loop. Accepted findings appear with full
LLM-justified rationale and a deep-link into the Temporal workflow trace.

---

## Configuration flags

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `-gitlab-token` | `GITLAB_TOKEN` | — | GitLab PAT (`read_api` + `read_repository`) |
| `-gitlab-project` | `GITLAB_PROJECT` | — | Project ID or `group/project` path |
| `-gitlab-url` | — | `https://gitlab.com/api/v4` | GitLab API base URL |
| `-llm` | — | `scripted` | `scripted` \| `anthropic` \| `claude-code` |
| `-model` | — | backend default | LLM model name override |
| `-addr` | — | `:8090` | HTTP listen address |
| `-temporal` | — | `localhost:7233` | Temporal server address |
| `-max-candidates` | — | `5` | Cap candidates per scanner (bounds LLM fan-out) |

---

## Build tags

| Tag | Effect |
|-----|--------|
| _(none)_ | Default. Pure-Go regex scanner. No CGO required. |
| `yara` | YARA-backed scanner. Requires `libyara` 4.3+ and `pkg-config`. |
| `sibyl_stub` | In-tree Sibyl stub. Scaffold/CI validation only. |

```sh
go build ./...                   # default
go build -tags yara ./...        # YARA scanner enabled
go build -tags sibyl_stub ./...  # stub mode
```

---

## Project layout

```
gitlab-sentinel/
├── gitlab/                    GitLab API client (blob search, MR diffs, issues)
├── scanners/
│   ├── gitlabscan/            GitLab scanner — blob search + MR diff scan
│   ├── regex/                 pure-Go regex secret scanner
│   ├── oauth/                 stale OAuth grant scanner
│   ├── scopes/                over-privilege scanner
│   └── dormancy/              dormant IAM account scanner
├── audit/                     SecurityAuditWorkflow + convergence orchestration
├── prompts/                   Researcher + Critic prompt templates
├── findings/                  shared Finding type, severity, evidence
├── rules/                     embedded regex patterns (+ YARA with build tag)
├── owners/                    finding → assignee resolution
├── jira/                      Jira ticket activity
├── okta/, aws/, github/       vendor HTTP clients
├── internal/sibylproxy/       Sibyl agent runtime interface
└── cmd/
    ├── sentry-web/            HTTP server + SSE UI (worker in-process)
    ├── sentry-worker/         standalone Temporal worker
    └── sentry-audit/          CLI: submit audit, print brief
```

---

## CI

Nine checks on every push and PR — all must pass before merge:

| Check | What it enforces |
|-------|-----------------|
| `go vet` | Correctness (default + sibyl_stub tags) |
| `gofmt` | Formatting |
| `go mod tidy` | Clean go.mod / go.sum |
| `build` | Compiles (default + sibyl_stub tags) |
| `test` | Unit tests with race detector |
| `coverage` | Coverage report uploaded as artifact |
| `staticcheck` | Full SA/ST/QF static analysis |
| `golangci-lint` | errcheck, bodyclose, errorlint, misspell, unconvert |
| `CI gate` | Single required status — all above must pass |

---

## Troubleshooting

**`go build` fails:** run `go mod tidy` first; ensure `go version` ≥ 1.24.

**GitLab scanner returns no findings:** confirm your PAT has `read_api` and
`read_repository` scopes. GitLab blob search requires code indexing enabled
on the project (default on gitlab.com).

**Temporal UI shows no workflows:** confirm `temporal server start-dev` is
running on `localhost:7233`; override with `-temporal`.

**Findings always rejected with `-llm scripted`:** expected — scripted mode
uses canned responses for plumbing verification only. Use `-llm anthropic`
or `-llm claude-code` to see real Researcher/Critic reasoning.

**Mock servers unreachable:** run `make check` in the fixtures repo; pass
`-okta-url` / `-aws-url` if they are on non-default ports.

---

## Related

- **[sibyl-sentry-fixtures](https://github.com/vinodhalaharvi/sibyl-sentry-fixtures)** — mock Okta + AWS servers with planted findings
- **[weft](https://github.com/vinodhalaharvi/weft)** — categorical arrow algebra for composing LLM + MCP pipelines in Go
- **[GitLab MCP server docs](https://docs.gitlab.com/user/gitlab_duo/model_context_protocol/)** — official GitLab MCP tool reference

---

*Google Cloud Rapid Agent Hackathon — GitLab track. Author: Vinod Halaharvi.*
