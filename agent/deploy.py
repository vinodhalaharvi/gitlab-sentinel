#!/usr/bin/env python3
"""
deploy.py — Deploy gitlab-sentinel-agent to Vertex AI Agent Engine.

Usage:
    export GOOGLE_CLOUD_PROJECT=your-project-id
    export SENTINEL_URL=https://gitlab-sentinel-xxxx-uc.a.run.app
    python agent/deploy.py

Requirements:
    pip install google-adk google-cloud-aiplatform
"""

import os
import sys

import vertexai
from vertexai import agent_engines
from agent.agent import root_agent

PROJECT  = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

if not PROJECT:
    print("ERROR: set GOOGLE_CLOUD_PROJECT", file=sys.stderr)
    sys.exit(1)

print(f"Deploying to project={PROJECT} location={LOCATION}...")

vertexai.init(project=PROJECT, location=LOCATION)

remote_agent = agent_engines.AdkApp(
    agent=root_agent,
    enable_tracing=True,
)

deployed = agent_engines.create(
    remote_agent,
    requirements=["google-adk>=1.0.0"],
    display_name="GitLab Sentinel",
    description=(
        "Agentic security scanner for GitLab — "
        "Google Cloud Rapid Agent Hackathon, GitLab track."
    ),
)

print(f"\n✅ Deployed: {deployed.resource_name}")
print(f"   Agent Engine ID: {deployed.name}")
print(f"\nTest it:")
print(f"  python agent/query.py '{deployed.resource_name}' 'scan mygroup/myrepo'")
