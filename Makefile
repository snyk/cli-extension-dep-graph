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

.PHONY: install-req fmt test lint tidy imports
