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

lint: install-tools
	.bin/golangci-lint run -v

tidy:
	$(GOMOD) tidy -v

test:
	$(GOTEST) ./... -coverprofile cp.out

test-python-integration:
	$(GOTEST) -v -tags="integration,python" -timeout=10m ./pkg/ecosystems/python/pip/ -coverprofile cp.out

# Python fixture regeneration
PYTHON_VERSIONS := 3.8 3.9 3.10 3.14
PYTHON_VERSION ?=

update-python-fixtures:
	@echo "Building update-fixtures tool..."
	@$(GOBUILD) -o .bin/update-fixtures ./tools/update-fixtures
	@if [ -n "$(PYTHON_VERSION)" ]; then \
		echo "Checking for Python $(PYTHON_VERSION)..."; \
		PYENV_ROOT=$$(pyenv root); \
		FOUND=0; \
		PYTHON_PATH=""; \
		for dir in $$PYENV_ROOT/versions/$(PYTHON_VERSION)*; do \
			if [ -d "$$dir" ]; then \
				FOUND=1; \
				PYTHON_PATH="$$dir/bin"; \
				break; \
			fi; \
		done; \
		if [ $$FOUND -eq 0 ]; then \
			echo ""; \
			echo "ERROR: Python $(PYTHON_VERSION) is not installed."; \
			echo ""; \
			echo "Install it with:"; \
			echo "  pyenv install $(PYTHON_VERSION)"; \
			echo ""; \
			exit 1; \
		fi; \
		echo "Using Python version:"; \
		PATH="$$PYTHON_PATH:$$PATH" python3 --version; \
		echo "Running update-fixtures..."; \
		PATH="$$PYTHON_PATH:$$PATH" .bin/update-fixtures; \
	else \
		echo "Using current Python version:"; \
		python3 --version; \
		echo "Running update-fixtures..."; \
		.bin/update-fixtures; \
	fi

update-python-fixtures-all:
	@echo "Regenerating fixtures for all Python versions..."
	@for version in $(PYTHON_VERSIONS); do \
		echo ""; \
		echo "========================================"; \
		echo "Updating fixtures for Python $$version"; \
		echo "========================================"; \
		$(MAKE) update-python-fixtures PYTHON_VERSION=$$version || { echo "Failed to update fixtures for Python $$version"; continue; }; \
	done
	@echo ""
	@echo "All fixtures updated!"

.PHONY: install-req fmt test test-python-integration lint tidy imports update-python-fixtures update-python-fixtures-all
