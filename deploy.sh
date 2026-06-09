#!/usr/bin/env bash
# deploy.sh — build and deploy gitlab-sentinel to Cloud Run in one command.
#
# Prerequisites:
#   gcloud auth login
#   gcloud auth configure-docker
#   gcloud config set project YOUR_PROJECT_ID
#
# Required env vars:
#   GOOGLE_CLOUD_PROJECT   GCP project ID
#   GITLAB_TOKEN           GitLab PAT (read_api + read_repository)
#   GITLAB_PROJECT         GitLab project ID or group/project path
#   GOOGLE_API_KEY         Gemini API key (or use ANTHROPIC_API_KEY + LLM_BACKEND=anthropic)
#
# Optional:
#   REGION                 GCP region (default: us-central1)
#   SERVICE                Cloud Run service name (default: gitlab-sentinel)
#   LLM_BACKEND            LLM backend (default: gemini)

set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-gitlab-sentinel}"
LLM="${LLM_BACKEND:-gemini}"
IMAGE="gcr.io/${PROJECT}/${SERVICE}"

if [[ -z "$PROJECT" ]]; then
  echo "ERROR: set GOOGLE_CLOUD_PROJECT or run 'gcloud config set project YOUR_PROJECT_ID'"
  exit 1
fi

if [[ -z "${GITLAB_TOKEN:-}" ]]; then
  echo "ERROR: GITLAB_TOKEN is required"
  exit 1
fi

if [[ -z "${GITLAB_PROJECT:-}" ]]; then
  echo "ERROR: GITLAB_PROJECT is required (e.g. 'mygroup/myrepo')"
  exit 1
fi

echo "▶ Building image: ${IMAGE}:latest"
docker build --platform linux/amd64 -t "${IMAGE}:latest" .

echo "▶ Pushing image"
docker push "${IMAGE}:latest"

echo "▶ Deploying to Cloud Run (${SERVICE} in ${REGION})"
gcloud run deploy "${SERVICE}" \
  --image="${IMAGE}:latest" \
  --region="${REGION}" \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=3 \
  --timeout=300 \
  --set-env-vars="LLM_BACKEND=${LLM}" \
  --update-secrets="GITLAB_TOKEN=gitlab-token:latest" \
  --update-secrets="GITLAB_PROJECT=gitlab-project:latest" \
  --update-secrets="GOOGLE_API_KEY=google-api-key:latest"

URL=$(gcloud run services describe "${SERVICE}" \
  --region="${REGION}" \
  --format="value(status.url)")

echo ""
echo "✅ Deployed: ${URL}"
echo ""
echo "Next: open ${URL} and click Run Audit"
