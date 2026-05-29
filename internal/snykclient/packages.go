package snykclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const packagesAPIVersion = "2024-10-15"

// MavenPackageQuery describes the input to the Snyk Packages endpoint when
// looking up the canonical Maven coordinates for an artifact identified by SHA1.
type MavenPackageQuery struct {
	Sha1     string
	GroupID  string
	Artifact string
	Version  string
}

// packagesResponse mirrors the relevant subset of the /rest/packages response.
type packagesResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// LookupMavenPackage resolves a Maven artifact's canonical coordinates by SHA1.
//
// It returns the package URL (purl string) of the canonical artifact as
// reported by the Packages service, or an empty string if the service has no
// record of the SHA1. Callers should treat the empty return as "no
// normalisation possible — keep the original coordinates".
//
// HTTP/JSON errors are returned so callers can decide whether to log and
// continue (the typical fallback) or surface the failure.
func (t *SnykClient) LookupMavenPackage(ctx context.Context, q MavenPackageQuery) (string, error) {
	u, err := buildPackagesAPIURL(t.apiBaseURL, q)
	if err != nil {
		return "", fmt.Errorf("failed to build packages API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("failed to create packages request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("packages request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 means the SHA1 is genuinely unknown to the Packages service; return
	// empty with no error so the caller falls back to the original coordinates
	// silently. This is the normal "no canonical mapping" path.
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	// Treat anything outside 2xx as an error, including 3xx. Redirects are
	// included because SnykClient wraps the underlying HTTP client with a
	// non-redirecting policy (http.ErrUseLastResponse), so a 3xx response
	// here means the redirect was intentionally not followed and is unexpected.
	// All non-404 failures are surfaced as errors so callers can log them;
	// normalize-deps remains best-effort so the caller still falls back to the
	// original coordinates rather than failing the scan.
	if resp.StatusCode >= 300 {
		return "", errorWithRequestID("packages request failed", resp)
	}

	var body packagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("failed to decode packages response: %w", err)
	}
	if len(body.Data) == 0 {
		return "", nil
	}
	return body.Data[0].ID, nil
}

// buildPackagesAPIURL constructs the /rest/packages query URL. The endpoint is
// org-agnostic at the path level; org context is provided via the API token.
func buildPackagesAPIURL(apiBaseURL string, q MavenPackageQuery) (*url.URL, error) {
	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API base URL: %w", err)
	}
	u = u.JoinPath("rest", "packages")

	query := url.Values{
		"version":      []string{packagesAPIVersion},
		"package_type": []string{"maven"},
	}
	if q.Sha1 != "" {
		query.Set("package_sha1", q.Sha1)
	}
	if q.GroupID != "" {
		query.Set("package_namespace", q.GroupID)
	}
	if q.Artifact != "" {
		query.Set("package_name", q.Artifact)
	}
	if q.Version != "" {
		query.Set("package_version", q.Version)
	}
	u.RawQuery = query.Encode()
	return u, nil
}
