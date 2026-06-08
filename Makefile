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

test-npm-integration:
	$(GOTEST) -v -tags="integration,npm" -timeout=10m ./pkg/ecosystems/javascript/npmlocked/ -coverprofile cp.out

# Run the npm integration suite across multiple npm major versions inside
# official Docker Hub node:<version> images. Mirrors the CircleCI matrix so
# devs without nvm/fnm can get coverage locally with one command. Requires
# Docker.
#
# Override NPM_MATRIX to add/remove versions:
#   make test-npm-matrix NPM_MATRIX="14 18 20 22"
#
# The node:<v> tag implies the bundled npm version. To pin a *different* npm
# inside a given image, edit the in-container `npm install -g npm@<x>` line.
NPM_MATRIX ?= 14 18 20 22
test-npm-matrix:
	@command -v docker >/dev/null || { echo "docker not in PATH"; exit 1; }
	@set -e; for v in $(NPM_MATRIX); do \
		echo "=== node:$$v ==="; \
		docker run --rm \
			-v "$$(pwd)":/src \
			-v "$${GOPATH:-$$HOME/go}/pkg":/go/pkg \
			-w /src \
			node:$$v sh -c "\
				set -e; \
				echo \"npm: \$$(npm --version)\"; \
				wget -qO- https://go.dev/dl/go1.26.3.linux-amd64.tar.gz | tar -C /usr/local -xz; \
				export PATH=\$$PATH:/usr/local/go/bin; \
				make test-npm-integration"; \
	done

update-gradle-fixtures:
	UPDATE_FIXTURES=1 $(GOTEST) -v -tags="integration,gradle" -timeout=15m ./pkg/ecosystems/gradle/

test-pnpm-integration:
	$(GOTEST) -v -tags="integration,pnpm" -timeout=10m ./pkg/ecosystems/javascript/pnpm/ -coverprofile cp.out

.PHONY: install-req fmt test test-bazel-jvm-integration test-bazel-go-integration test-python-integration test-gradle-integration test-pnpm-integration test-npm-integration test-npm-matrix update-gradle-fixtures lint tidy imports install-golangci-lint
