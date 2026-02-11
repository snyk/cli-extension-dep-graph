SHELL := /bin/bash

GOCMD=go
GOMOD=$(GOCMD) mod
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

GOLANGCI_LINT_V=v2.9.0

all:
	$(info  "completed running make file for golang project")

fmt:
	@go fmt ./...

install-tools:
	@echo "Installing golangci-lint..."
	@mkdir -p .bin
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_V)/install.sh | sh -s -- -b .bin $(GOLANGCI_LINT_V)

lint:
	$(if $(CI),golangci-lint,.bin/golangci-lint) run -v

tidy:
	$(GOMOD) tidy -v

test:
	$(GOTEST) ./... -coverprofile cp.out

test-python-integration:
	$(GOTEST) -v -tags="integration,python" -timeout=10m ./pkg/ecosystems/python/pip/ -coverprofile cp.out

.PHONY: install-req fmt test test-python-integration lint tidy imports
