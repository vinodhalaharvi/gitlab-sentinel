"""
gitlab_sentinel_agent — Google ADK agent that translates natural language
security scan requests into calls to the gitlab-sentinel backend.

Architecture (category-theoretic framing):
    UserIntent  ──η──▶  RunRequest  ──Arrow──▶  AuditOutput
       (NL)             (typed)                  (findings)

  η  = this agent: the natural transformation from unstructured intent
       to the typed RunRequest that SecurityAuditWorkflow expects.
  Arrow = the full categorical composition inside gitlab-sentinel
          (scanners → Researcher/Critic → synthesis). Unchanged.

The agent has one primary tool: scan_project.
It calls POST /run on the gitlab-sentinel Cloud Run service, returns
the workflow_id, and tells the user where to monitor the live audit.

Deploy:
    pip install google-adk
    export GOOGLE_CLOUD_PROJECT=your-project
    export SENTINEL_URL=https://gitlab-sentinel-xxxx-uc.a.run.app
    adk deploy agent/ --display-name="GitLab Sentinel" --region=us-central1

Or locally:
    adk run agent/
"""

import os
import urllib.request
import urllib.error
import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

# ── Config ────────────────────────────────────────────────────────────────────
SENTINEL_URL = os.environ.get(
    "SENTINEL_URL",
    "http://localhost:8090",   # local dev default
).rstrip("/")

MODEL = os.environ.get("SENTINEL_AGENT_MODEL", "gemini-2.5-flash")

# ── Tools ─────────────────────────────────────────────────────────────────────

def scan_project(
    project: str,
    scanners: str = "all",
) -> dict:
    """Start a security audit on a GitLab project using GitLab Sentinel.

    Scans the project for secrets in code, stale OAuth grants,
    over-privileged scopes, and dormant IAM accounts. Every candidate
    finding is debated by a Researcher/Critic agent pair before being
    accepted — so you only see findings that survived adversarial review.

    Args:
        project: GitLab project path (e.g. 'mygroup/myrepo') or numeric ID.
                 Leave empty to use the server's configured default project.
        scanners: Comma-separated list of scanners to enable, or 'all'.
                  Options: gitlab, secrets, oauth, scopes, dormancy.
                  Default: 'all'.

    Returns:
        dict with workflow_id (use to monitor progress) and monitor_url.
    """
    payload: dict = {}
    if project and project.lower() not in ("", "default", "all"):
        payload["gitlab_project"] = project

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{SENTINEL_URL}/run",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}

    wf_id = result.get("workflow_id", "")
    return {
        "workflow_id": wf_id,
        "status": "started",
        "monitor_url": f"{SENTINEL_URL}/?workflow_id={wf_id}",
        "events_url": f"{SENTINEL_URL}/events?workflow_id={wf_id}",
        "message": (
            f"Security audit started for '{project or 'default project'}'. "
            f"Workflow ID: {wf_id}. "
            f"Monitor live at: {SENTINEL_URL}"
        ),
    }


def get_audit_report(workflow_id: str) -> dict:
    """Fetch the completed report for a finished security audit.

    Call this after scan_project once the audit has had time to complete
    (typically 30–120 seconds depending on project size).

    Args:
        workflow_id: The workflow_id returned by scan_project.

    Returns:
        dict with findings (accepted by Critic) and rejected (false positives
        caught by Critic). Each finding includes title, severity, description,
        scanner, and the Researcher/Critic debate rationale.
    """
    url = f"{SENTINEL_URL}/report?workflow_id={urllib.parse.quote(workflow_id)}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}

    rep = raw.get("Report") or raw.get("report") or {}
    findings = rep.get("Findings") or rep.get("findings") or []
    rejected = rep.get("Rejected") or rep.get("rejected") or []

    # Summarise for the agent — full JSON is too large for a chat response.
    summary = {
        "findings_count": len(findings),
        "rejected_count": len(rejected),
        "findings": [
            {
                "title": f.get("Title") or f.get("title"),
                "severity": str(f.get("Severity") or f.get("severity")),
                "scanner": f.get("ScannerID") or f.get("scanner_id"),
                "rationale": (f.get("LLMRationale") or f.get("llm_rationale") or "")[:300],
            }
            for f in findings
        ],
        "false_positives_caught": len(rejected),
        "monitor_url": f"{SENTINEL_URL}",
    }
    return summary


def check_health() -> dict:
    """Check that the gitlab-sentinel backend is healthy and reachable.

    Returns:
        dict with status 'ok' or an error message.
    """
    try:
        with urllib.request.urlopen(f"{SENTINEL_URL}/healthz", timeout=10) as resp:
            return {"status": resp.read().decode().strip(), "url": SENTINEL_URL}
    except Exception as e:
        return {"status": "error", "error": str(e), "url": SENTINEL_URL}


# urllib.parse needed for get_audit_report
import urllib.parse  # noqa: E402 — imported after use in docstring

# ── Agent ─────────────────────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = """
You are GitLab Sentinel — an agentic security scanner for GitLab repositories.

Your job is to help developers scan their GitLab projects for security issues
using the GitLab Sentinel backend. You orchestrate scans, report findings, and
explain what the AI found and why.

## What you can do

- Start a security scan on any GitLab project
- Check if a scan has completed and fetch its findings
- Explain findings and their severity
- Tell the user where to monitor the live scan in real time

## How the backend works (so you can explain it accurately)

GitLab Sentinel runs five parallel scanners:
  1. GitLab scanner — searches code blobs and open MR diffs for secrets
     (AWS keys, GitLab PATs, GitHub tokens, private keys, etc.)
  2. Secrets scanner — regex patterns across the local file tree
  3. OAuth scanner — finds OAuth grants unused for 365+ days
  4. Scopes scanner — finds OAuth clients with over-privileged permissions
  5. Dormancy scanner — finds AWS IAM accounts with stale access keys

Every candidate finding is put through an adversarial Researcher/Critic debate:
  - The Researcher proposes: "this looks like a real credential, here's why"
  - The Critic demands evidence and rejects anything that could be a false positive
  - Up to 3 rounds of debate before a verdict
  - Only findings that survive the Critic reach the final report

This means you only surface findings that withstood adversarial AI review.

## Tone

Be direct and technical. Security engineers don't want fluff.
If a CRITICAL finding is found, be clear about the urgency.
Always provide the workflow_id and monitor URL so the user can watch live.
"""

root_agent = LlmAgent(
    name="gitlab_sentinel_agent",
    model=MODEL,
    description=(
        "Agentic security scanner for GitLab — scans repositories for secrets, "
        "stale OAuth grants, over-privileged scopes, and dormant IAM accounts. "
        "Every finding is debated by a Researcher/Critic pair before surfacing."
    ),
    instruction=SYSTEM_INSTRUCTION,
    tools=[
        FunctionTool(scan_project),
        FunctionTool(get_audit_report),
        FunctionTool(check_health),
    ],
)
