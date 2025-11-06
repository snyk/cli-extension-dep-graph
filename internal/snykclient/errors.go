package snykclient

import (
	"fmt"
	"net/http"
)

func errorWithRequestID(message string, r *http.Response) error {
	requestID := r.Header.Get("snyk-request-id")

	if requestID == "" {
		return fmt.Errorf("%s (%s)", message, r.Status)
	}

	return fmt.Errorf("%s (%s - requestId: %s)", message, r.Status, requestID)
}

type ClientError struct {
	err     error
	userMsg string
}

func (e ClientError) Error() string {
	return e.userMsg
}

func (e ClientError) Unwrap() error {
	return e.err
}

func NewEmptyOrgError() *ClientError {
	return &ClientError{
		err: fmt.Errorf("failed to determine org id"),
		userMsg: "Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. " +
			"Should the issue persist, explicitly set an organization ID via the `--org` flag.",
	}
}

func NewSCAError(err error) *ClientError {
	return &ClientError{
		err:     err,
		userMsg: fmt.Sprintf("There was an error while analyzing the SBOM document: %s", err),
	}
}
