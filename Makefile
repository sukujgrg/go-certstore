GOCACHE ?= $(CURDIR)/.gocache
GO ?= go
LIB_COVER ?= .cover.out
EXAMPLES := ./examples/list-identities ./examples/tls-client ./examples/export-cert
PKGSITE ?= pkgsite
GOLANGCI_LINT ?= golangci-lint
DOC_ADDR ?= localhost:6060

.PHONY: check check-linux check-macos test lint cover examples docs clean

check: test

# On Linux, prefer running `make check` directly. `check-linux` exists mainly
# for non-Linux hosts that want a Linux preflight via Docker.
check-linux:
	./scripts/check-linux.sh

check-macos: check
	CERTSTORE_RUN_NATIVE_TESTS=1 GOCACHE="$(GOCACHE)" $(GO) test -run TestMacKeychainIntegration -v

test:
	GOCACHE="$(GOCACHE)" $(GO) test ./...

lint:
	@command -v "$(GOLANGCI_LINT)" >/dev/null 2>&1 || { \
		echo "golangci-lint not found; install with: $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	}
	GOCACHE="$(GOCACHE)" "$(GOLANGCI_LINT)" run

cover:
	GOCACHE="$(GOCACHE)" $(GO) test . -coverprofile="$(LIB_COVER)"
	GOCACHE="$(GOCACHE)" $(GO) tool cover -func="$(LIB_COVER)"

examples:
	GOCACHE="$(GOCACHE)" $(GO) build $(EXAMPLES)

docs:
	@command -v "$(PKGSITE)" >/dev/null 2>&1 || { \
		echo "pkgsite not found; install with: $(GO) install golang.org/x/pkgsite/cmd/pkgsite@latest"; \
		exit 1; \
	}
	@echo "Serving docs at http://$(DOC_ADDR)/github.com/sukujgrg/go-certstore"
	GOCACHE="$(GOCACHE)" "$(PKGSITE)" -http="$(DOC_ADDR)"

clean:
	rm -f "$(LIB_COVER)"
