#!/usr/bin/env bash
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.27.0
$GOPATH/bin/golangci-lint run -v