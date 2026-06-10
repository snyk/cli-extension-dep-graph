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

install-golangci-lint:
	@if [ -x .bin/golangci-lint ] && .bin/golangci-lint version 2>&1 | grep -q "$(GOLANGCI_LINT_V:v%=%)"; then \
		echo "golangci-lint $(GOLANGCI_LINT_V) already installed."; \
	else \
		echo "Installing golangci-lint $(GOLANGCI_LINT_V)..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_V)/install.sh | sh -s -- -b .bin $(GOLANGCI_LINT_V); \
	fi

install-tools:
	@mkdir -p .bin
	@$(MAKE) install-golangci-lint

lint: install-tools
	.bin/golangci-lint run -v

tidy:
	$(GOMOD) tidy -v

test:
	$(GOTEST) ./... -coverprofile cp.out

test-bazel-jvm-integration:
	BAZEL_JVM_INTEGRATION_TESTS=1 $(GOTEST) -timeout=10m -coverprofile cp.out ./pkg/ecosystems/bazel/...

test-bazel-go-integration:
	BAZEL_GO_INTEGRATION_TESTS=1 $(GOTEST) -timeout=10m -coverprofile cp.out ./pkg/ecosystems/bazel/...

test-python-integration:
	$(GOTEST) -v -tags="integration,python" -timeout=10m ./pkg/ecosystems/python/pip/ -coverprofile cp.out

test-gradle-integration:
	$(GOTEST) -v -tags="integration,gradle" -timeout=15m ./pkg/ecosystems/gradle/ -coverprofile cp.out

test-cocoapods-integration:
	$(GOTEST) -v -tags="integration,cocoapods" -timeout=10m ./pkg/ecosystems/cocoa/cocoapods/ -coverprofile cp.out

update-gradle-fixtures:
	UPDATE_FIXTURES=1 $(GOTEST) -v -tags="integration,gradle" -timeout=15m ./pkg/ecosystems/gradle/

.PHONY: install-req fmt test test-bazel-jvm-integration test-bazel-go-integration test-python-integration test-gradle-integration test-cocoapods-integration update-gradle-fixtures lint tidy imports install-golangci-lint
