GOCACHE ?= $(CURDIR)/.gocache
GO ?= go
LIB_COVER ?= .cover.out
EXAMPLES := ./examples/list-identities ./examples/tls-client ./examples/export-cert
PKGSITE ?= pkgsite
DOC_ADDR ?= localhost:6060

.PHONY: test cover examples docs clean

test:
	GOCACHE="$(GOCACHE)" $(GO) test ./...

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
