package snykclient

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

func errorWithRequestID(message string, r *http.Response) error {
	requestID := r.Header.Get("snyk-request-id")

	if requestID == "" {
		return fmt.Errorf("%s (%s)", message, r.Status)
	}

	return fmt.Errorf("%s (%s - requestId: %s)", message, r.Status, requestID)
}

type SBOMExtensionError struct {
	err     error
	userMsg string
}

func (e SBOMExtensionError) Error() string {
	return e.userMsg
}

func (e SBOMExtensionError) Unwrap() error {
	return e.err
}

type ErrorFactory struct {
	logger *zerolog.Logger
}

func NewErrorFactory(logger *zerolog.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

func (ef *ErrorFactory) newErr(err error, userMsg string) *SBOMExtensionError {
	ef.logger.Printf("ERROR: %s\n", err)

	return &SBOMExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}

func (ef *ErrorFactory) NewEmptyOrgError() *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("failed to determine org id"),
		"Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
			"Should the issue persist, explicitly set an organization ID via the `--org` flag.",
	)
}

func (ef *ErrorFactory) NewSCAError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		fmt.Sprintf("There was an error while analyzing the SBOM document: %s", err),
	)
}
