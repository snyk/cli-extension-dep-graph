SHELL := /bin/bash

GOCMD=go
GOMOD=$(GOCMD) mod
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

all:
	$(info  "completed running make file for golang project")
fmt:
	@go fmt ./...
lint:
	./script/lint.sh
tidy:
	$(GOMOD) tidy -v
test:
	$(GOTEST) ./... -coverprofile cp.out

test-python-integration:
	$(GOTEST) -v -tags="integration,python" -timeout=10m ./pkg/ecosystems/python/pip/

.PHONY: install-req fmt test test-python-integration lint tidy imports
