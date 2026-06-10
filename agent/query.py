#!/usr/bin/env python3
"""
query.py — Send a query to the deployed GitLab Sentinel agent.

Usage:
    python agent/query.py <resource_name> "<message>"

Example:
    python agent/query.py projects/my-proj/locations/us-central1/reasoningEngines/123 \
        "scan vinodhalaharvi/gitlab-sentinel for secrets"
"""

import sys
import vertexai
from vertexai import agent_engines

if len(sys.argv) < 3:
    print("Usage: query.py <resource_name> <message>")
    sys.exit(1)

resource_name = sys.argv[1]
message = sys.argv[2]

# Extract project/location from resource name
# projects/PROJECT/locations/LOCATION/reasoningEngines/ID
parts = resource_name.split("/")
project  = parts[1] if len(parts) > 1 else None
location = parts[3] if len(parts) > 3 else "us-central1"

vertexai.init(project=project, location=location)

agent = agent_engines.get(resource_name)
session = agent.create_session(user_id="demo-user")

print(f"Session: {session['id']}")
print(f"Query: {message}\n")

for event in agent.stream_query(
    user_id="demo-user",
    session_id=session["id"],
    message=message,
):
    for part in event.get("content", {}).get("parts", []):
        if "text" in part:
            print(part["text"], end="", flush=True)
        elif "function_call" in part:
            fc = part["function_call"]
            print(f"\n[tool call: {fc['name']}({fc.get('args', {})})]")
        elif "function_response" in part:
            fr = part["function_response"]
            print(f"\n[tool response: {fr['name']} → {str(fr.get('response',''))[:120]}]")

print()
