// Package gitlabscan is a Temporal activity that scans a GitLab project
// for security issues using the GitLab REST API (the same endpoints exposed
// by the official GitLab MCP server).
//
// Two scan passes:
//  1. Blob search — queries GitLab's code search for known secret patterns
//     (API keys, tokens, private keys) across the entire project.
//  2. MR diff scan — fetches open merge request diffs and applies the same
//     regex rules, catching secrets introduced in in-flight changes before
//     they land in the default branch.
//
// The findings produced here are structurally identical to those from the
// regex scanner — same Finding type, same Evidence shape — so the
// Researcher/Critic convergence loop works unchanged.
package gitlabscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"

	"github.com/vinodhalaharvi/gitlab-sentinel/findings"
	"github.com/vinodhalaharvi/gitlab-sentinel/gitlab"
	"github.com/vinodhalaharvi/gitlab-sentinel/internal/sibylproxy"
)

// ActivityName is the Temporal activity registration name.
const ActivityName = "gitlab.Scan"

// ScanInput is the activity input.
type ScanInput struct {
	// ProjectID is the GitLab project ID or URL-encoded path, e.g.
	// "42" or "mygroup%2Fmyproject". Required.
	ProjectID string

	// GitLabBaseURL is the GitLab API base, e.g. "https://gitlab.com/api/v4".
	// Defaults to "https://gitlab.com/api/v4".
	GitLabBaseURL string

	// GitLabToken is a Personal Access Token with read_api + read_repository.
	GitLabToken string

	// ScanMRDiffs, if true, also scans open MR diffs. Useful for catching
	// secrets before they land in the default branch.
	ScanMRDiffs bool

	// MaxMRs caps how many open MRs to diff-scan. Default 10.
	MaxMRs int
}

// ScanOutput is the activity output.
type ScanOutput struct {
	Findings      []findings.Finding
	BlobsSearched int
	MRsScanned    int
}

// secretQuery is one blob-search query + metadata.
type secretQuery struct {
	query       string // search term sent to GitLab blob search
	ruleID      string // matches severityFor() and findingID()
	description string // human-readable label
	pattern     *regexp.Regexp // local confirmation filter (reduces false positives from GitLab's fuzzy search)
}

// secretQueries are the patterns we search for via GitLab's blob search API.
// GitLab's code search is keyword-based, so we pick high-signal terms that
// appear in real credentials, then apply a local regex to confirm the match.
var secretQueries = []secretQuery{
	{
		query:       "AKIA",
		ruleID:      "aws_access_key",
		description: "AWS access key ID",
		pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		query:       "glpat-",
		ruleID:      "gitlab_pat",
		description: "GitLab Personal Access Token",
		pattern:     regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`),
	},
	{
		query:       "ghp_",
		ruleID:      "github_pat",
		description: "GitHub Personal Access Token",
		pattern:     regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	},
	{
		query:       "-----BEGIN RSA PRIVATE KEY-----",
		ruleID:      "private_key_pem",
		description: "RSA private key",
		pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	},
	{
		query:       "sk-ant-",
		ruleID:      "anthropic_api_key",
		description: "Anthropic API key",
		pattern:     regexp.MustCompile(`sk-ant-[0-9a-zA-Z\-_]{40,}`),
	},
	{
		query:       "xoxb-",
		ruleID:      "slack_token",
		description: "Slack bot token",
		pattern:     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`),
	},
	{
		query:       "AIza",
		ruleID:      "google_api_key",
		description: "Google API key",
		pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	},
}

// Scan is the Temporal activity entrypoint.
func Scan(ctx context.Context, in ScanInput) (*ScanOutput, error) {
	const nodeID = "gitlab"
	const label = "GitLab"
	started := time.Now()
	emitter := sibylproxy.EmitterForActivity(ctx)
	emitter.Emit(sibylproxy.NewNodeStarted("", nodeID, label))

	if in.ProjectID == "" {
		err := fmt.Errorf("gitlabscan.Scan: ProjectID required")
		emitter.Emit(sibylproxy.NewNodeFailed("", nodeID, label, err, time.Since(started)))
		return nil, err
	}
	if in.MaxMRs <= 0 {
		in.MaxMRs = 10
	}

	client := gitlab.New(in.GitLabBaseURL, in.GitLabToken)
	out := &ScanOutput{}

	// Pass 1: blob search for each secret pattern.
	for i, q := range secretQueries {
		if i%3 == 0 {
			heartbeat(ctx, fmt.Sprintf("blob search %d/%d", i, len(secretQueries)))
		}
		results, err := client.SearchBlobs(ctx, in.ProjectID, q.query, 20)
		if err != nil {
			// Non-fatal: log and continue. The scanner shouldn't abort because
			// one query rate-limited or the project is private for that scope.
			if activity.IsActivity(ctx) {
				activity.GetLogger(ctx).Warn("blob search failed",
					"query", q.query, "err", err)
			}
			continue
		}
		out.BlobsSearched += len(results)
		for _, r := range results {
			// Confirm the match locally with the tighter regex.
			matches := q.pattern.FindAllString(r.Data, -1)
			if len(matches) == 0 {
				continue
			}
			for _, match := range matches {
				loc := fmt.Sprintf("%s:%d", r.Path, r.Startline)
				out.Findings = append(out.Findings, findings.Finding{
					ID:       findingID(q.ruleID, loc, match),
					Category: findings.CategorySecretExposure,
					Severity: severityForRule(q.ruleID),
					Title: fmt.Sprintf("%s found in %s",
						q.description, r.Path),
					Description: fmt.Sprintf(
						"A %s was detected in %s at line %d. "+
							"If this is a real credential, rotate it immediately. "+
							"If it is a test fixture, add a comment or rename the "+
							"variable to make the intent explicit.",
						q.description, r.Path, r.Startline,
					),
					Evidence: []findings.Evidence{{
						Kind:        "gitlab_blob_search",
						Description: fmt.Sprintf("GitLab code search matched %q in %s", q.query, r.Path),
						Location:    loc,
						Snippet:     truncate(match, 120),
					}},
					OwnerHint:    r.Path,
					DiscoveredAt: time.Now().UTC(),
					ScannerID:    "gitlab",
				})
			}
		}
	}

	// Pass 2: MR diff scan (optional).
	if in.ScanMRDiffs {
		mrs, err := client.ListOpenMRs(ctx, in.ProjectID, in.MaxMRs)
		if err != nil {
			if activity.IsActivity(ctx) {
				activity.GetLogger(ctx).Warn("MR list failed", "err", err)
			}
		} else {
			for _, mr := range mrs {
				heartbeat(ctx, fmt.Sprintf("scanning MR !%d", mr.IID))
				diffs, err := client.GetMRDiffs(ctx, in.ProjectID, mr.IID)
				if err != nil {
					continue
				}
				out.MRsScanned++
				for _, diff := range diffs {
					out.Findings = append(out.Findings,
						scanDiff(diff, mr)...)
				}
			}
		}
	}

	emitter.Emit(sibylproxy.NewNodeCompleted("", nodeID, label,
		map[string]interface{}{
			"blobs_searched": out.BlobsSearched,
			"mrs_scanned":    out.MRsScanned,
			"findings_count": len(out.Findings),
		},
		time.Since(started),
	))
	return out, nil
}

// scanDiff applies all secret patterns to the added lines of a MR diff.
func scanDiff(diff gitlab.MRDiff, mr gitlab.MergeRequest) []findings.Finding {
	var fs []findings.Finding
	// Only scan added lines (prefixed with "+") to avoid re-flagging
	// things that were deleted.
	var added strings.Builder
	lineNum := 0
	for _, line := range strings.Split(diff.Diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added.WriteString(line[1:]) // strip leading "+"
			added.WriteByte('\n')
		}
		lineNum++
	}
	content := added.String()
	if content == "" {
		return nil
	}

	for _, q := range secretQueries {
		matches := q.pattern.FindAllString(content, -1)
		for _, match := range matches {
			loc := fmt.Sprintf("%s (MR !%d)", diff.NewPath, mr.IID)
			fs = append(fs, findings.Finding{
				ID:       findingID(q.ruleID+"-mr", loc, match),
				Category: findings.CategorySecretExposure,
				// MR findings are HIGH by default — the secret isn't in the
				// default branch yet, but it's in a diff that could be merged.
				Severity: findings.SeverityHigh,
				Title: fmt.Sprintf("%s introduced in MR !%d (%s)",
					q.description, mr.IID, mr.Title),
				Description: fmt.Sprintf(
					"A %s appears in the diff for merge request !%d '%s' "+
						"(branch %s → %s). If this is a real credential, "+
						"remove it from the MR before merging and rotate it.",
					q.description, mr.IID, mr.Title,
					mr.SourceBranch, mr.TargetBranch,
				),
				Evidence: []findings.Evidence{{
					Kind:        "mr_diff",
					Description: fmt.Sprintf("Pattern matched in diff of %s (MR !%d)", diff.NewPath, mr.IID),
					Location:    loc,
					Snippet:     truncate(match, 120),
				}, {
					Kind:        "mr_url",
					Description: "Merge request URL",
					Location:    mr.WebURL,
				}},
				OwnerHint:    mr.AuthorName,
				DiscoveredAt: time.Now().UTC(),
				ScannerID:    "gitlab",
			})
		}
	}
	return fs
}

// --- helpers ---

func findingID(ruleID, location, snippet string) string {
	h := sha256.Sum256([]byte(ruleID + "|" + location + "|" + snippet))
	return "gl-" + ruleID + "-" + hex.EncodeToString(h[:6])
}

func severityForRule(ruleID string) findings.Severity {
	switch ruleID {
	case "aws_access_key", "private_key_pem", "anthropic_api_key":
		return findings.SeverityHigh
	case "gitlab_pat", "github_pat":
		return findings.SeverityHigh
	case "google_api_key":
		return findings.SeverityMedium
	default:
		return findings.SeverityMedium
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func heartbeat(ctx context.Context, details ...interface{}) {
	if !activity.IsActivity(ctx) {
		return
	}
	activity.RecordHeartbeat(ctx, details...)
}
