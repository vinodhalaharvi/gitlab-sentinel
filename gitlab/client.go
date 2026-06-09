// Package gitlab provides a client for the official GitLab MCP server.
//
// It spawns `docker run gitlab/mcp-server:latest` (or a locally installed
// binary) as a subprocess over stdio, lifts the tools we need into typed
// Go calls, and exposes them for the scanner activities.
//
// Tools used:
//   - search (scope: blobs)      — find secrets in repo code
//   - get_merge_request_diffs   — scan MR diff content
//   - create_issue              — file a security issue for accepted findings
//
// The client is safe for concurrent use; each call is independent JSON-RPC.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is a thin REST client for the GitLab API (v4).
// For the hackathon we call the GitLab REST API directly rather than
// spawning the MCP server subprocess — the MCP server requires Docker
// and is better suited for Claude Desktop integrations. The scanner
// activities call this client, which wraps the same endpoints the
// GitLab MCP server exposes.
type Client struct {
	baseURL    string // e.g. https://gitlab.com/api/v4
	token      string
	httpClient *http.Client
}

// New creates a GitLab API client.
//   - baseURL: e.g. "https://gitlab.com/api/v4"
//   - token:   Personal Access Token with read_api + read_repository scopes
func New(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://gitlab.com/api/v4"
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// --- Response types ---

// BlobSearchResult is one result from GET /projects/:id/search?scope=blobs.
type BlobSearchResult struct {
	Basename  string `json:"basename"`
	Data      string `json:"data"`     // snippet of file content around the match
	Path      string `json:"path"`
	Filename  string `json:"filename"`
	ID        string `json:"id"`       // blob SHA
	Ref       string `json:"ref"`
	Startline int    `json:"startline"`
	ProjectID int    `json:"project_id"`
}

// MRDiff is one file diff from GET /projects/:id/merge_requests/:iid/diffs.
type MRDiff struct {
	Diff        string `json:"diff"`
	NewPath     string `json:"new_path"`
	OldPath     string `json:"old_path"`
	NewFile     bool   `json:"new_file"`
	RenamedFile bool   `json:"renamed_file"`
	DeletedFile bool   `json:"deleted_file"`
}

// MergeRequest is a summary of one MR.
type MergeRequest struct {
	IID          int    `json:"iid"`
	Title        string `json:"title"`
	State        string `json:"state"` // opened, merged, closed
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
	WebURL       string `json:"web_url"`
	AuthorName   string `json:"-"` // populated from author.name
	Author       struct {
		Name string `json:"name"`
	} `json:"author"`
}

// Issue represents a created GitLab issue.
type Issue struct {
	IID    int    `json:"iid"`
	WebURL string `json:"web_url"`
	Title  string `json:"title"`
}

// --- Methods ---

// SearchBlobs searches for a keyword across all blobs (files) in a project.
// Returns up to perPage results. GitLab's blob search returns a snippet of
// context around each match — ideal for the secret scanner.
func (c *Client) SearchBlobs(ctx context.Context, projectID, query string, perPage int) ([]BlobSearchResult, error) {
	if perPage <= 0 {
		perPage = 20
	}
	path := fmt.Sprintf("projects/%s/search?scope=blobs&search=%s&per_page=%d",
		urlEncode(projectID), urlEncode(query), perPage)
	var out []BlobSearchResult
	if err := c.getJSON(ctx, path, &out); err != nil {
		return nil, fmt.Errorf("gitlab.SearchBlobs: %w", err)
	}
	return out, nil
}

// ListOpenMRs returns open merge requests for the project.
func (c *Client) ListOpenMRs(ctx context.Context, projectID string, perPage int) ([]MergeRequest, error) {
	if perPage <= 0 {
		perPage = 20
	}
	path := fmt.Sprintf("projects/%s/merge_requests?state=opened&per_page=%d",
		urlEncode(projectID), perPage)
	var out []MergeRequest
	if err := c.getJSON(ctx, path, &out); err != nil {
		return nil, fmt.Errorf("gitlab.ListOpenMRs: %w", err)
	}
	// Flatten nested author name.
	for i := range out {
		out[i].AuthorName = out[i].Author.Name
	}
	return out, nil
}

// GetMRDiffs returns the file diffs for a merge request.
func (c *Client) GetMRDiffs(ctx context.Context, projectID string, mrIID int) ([]MRDiff, error) {
	path := fmt.Sprintf("projects/%s/merge_requests/%d/diffs",
		urlEncode(projectID), mrIID)
	var out []MRDiff
	if err := c.getJSON(ctx, path, &out); err != nil {
		return nil, fmt.Errorf("gitlab.GetMRDiffs: %w", err)
	}
	return out, nil
}

// CreateIssue files a new security issue in the project.
// Returns the created issue's IID and web URL.
func (c *Client) CreateIssue(ctx context.Context, projectID, title, description string, labels []string) (*Issue, error) {
	body := map[string]interface{}{
		"title":       title,
		"description": description,
	}
	if len(labels) > 0 {
		body["labels"] = strings.Join(labels, ",")
	}

	path := fmt.Sprintf("projects/%s/issues", urlEncode(projectID))
	var out Issue
	if err := c.postJSON(ctx, path, body, &out); err != nil {
		return nil, fmt.Errorf("gitlab.CreateIssue: %w", err)
	}
	return &out, nil
}

// --- HTTP helpers ---

func (c *Client) getJSON(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) postJSON(ctx context.Context, path string, body, out interface{}) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/"+path, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// urlEncode percent-encodes a project ID or path for use in a URL segment.
// GitLab accepts both numeric IDs and URL-encoded namespace/project paths.
func urlEncode(s string) string {
	// Replace / with %2F for project paths like "group/project".
	return strings.ReplaceAll(s, "/", "%2F")
}
