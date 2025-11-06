package snykclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
)

const (
	sbomConvertAPIVersion = "2025-03-06"
	MIMETypeOctetStream   = "application/octet-stream"
	ContentTypeHeader     = "Content-Type"
	ContentEncodingHeader = "Content-Encoding"
)

func (t *SnykClient) SBOMConvert(
	ctx context.Context,
	logger *zerolog.Logger,
	sbom io.Reader,
	remoteRepoURL string,
) ([]*ScanResult, []*ConversionWarning, error) {
	u, err := buildSBOMConvertAPIURL(t.apiBaseURL, sbomConvertAPIVersion, t.orgID, remoteRepoURL)
	if err != nil {
		logger.Printf("ERROR: failed to build SBOM convert API URL: %s\n", err)
		return nil, nil, NewSCAError(err)
	}

	body := bytes.NewBuffer(nil)
	writer := gzip.NewWriter(body)
	_, err = io.Copy(writer, sbom)
	if err != nil {
		logger.Printf("ERROR: failed to compress SBOM content: %s\n", err)
		return nil, nil, NewSCAError(err)
	}
	err = writer.Close()
	if err != nil {
		logger.Printf("ERROR: failed to close gzip writer: %s\n", err)
		return nil, nil, NewSCAError(err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u.String(),
		body,
	)
	if err != nil {
		logger.Printf("ERROR: failed to create HTTP request for SBOM conversion: %s\n", err)
		return nil, nil, NewSCAError(err)
	}

	req.Header.Set(ContentTypeHeader, MIMETypeOctetStream)
	req.Header.Set(ContentEncodingHeader, "gzip")

	resp, err := t.client.Do(req)
	if err != nil {
		logger.Printf("ERROR: failed to execute HTTP request for SBOM conversion: %s\n", err)
		return nil, nil, NewSCAError(err)
	}
	defer resp.Body.Close() //nolint:errcheck // errors in deferred close are not critical

	if resp.StatusCode > 399 && resp.StatusCode < 500 {
		reqErr := errorWithRequestID("request to analyze SBOM document was rejected", resp)
		logger.Printf("ERROR: request to analyze SBOM document was rejected: %s\n", reqErr)
		return nil, nil, NewSCAError(reqErr)
	}

	if resp.StatusCode > 499 {
		reqErr := errorWithRequestID("analysis of SBOM document failed due to error", resp)
		logger.Printf("ERROR: analysis of SBOM document failed due to error: %s\n", reqErr)
		return nil, nil, NewSCAError(reqErr)
	}

	var convertResp SBOMConvertResponse
	err = json.NewDecoder(resp.Body).Decode(&convertResp)
	if err != nil {
		logger.Printf("ERROR: failed to decode SBOM conversion response: %s\n", err)
		return nil, nil, NewSCAError(err)
	}

	return convertResp.ScanResults, convertResp.ConversionWarning, nil
}

func buildSBOMConvertAPIURL(apiBaseURL, apiVersion, orgID, remoteRepoURL string) (*url.URL, error) {
	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, err
	}

	u = u.JoinPath("hidden", "orgs", orgID, "sboms", "convert")

	query := url.Values{
		"version":         []string{apiVersion},
		"remote_repo_url": []string{remoteRepoURL},
	}
	u.RawQuery = query.Encode()

	return u, nil
}
