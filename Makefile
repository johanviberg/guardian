BINARY    := guardian
PKG       := ./cmd/guardian
GOBIN     := $(shell go env GOPATH)/bin
# Pinned tool versions — keep in sync with .github/workflows/ci.yml so local
# `make ci` and the CI gate run identical binaries.
GOVULNCHECK_VERSION := v1.3.0
GOSEC_VERSION       := v2.26.1
STATICCHECK_VERSION := v0.7.0
# Our own packages (everything except the vendored Bumblebee tree).
OWN_PKGS  := $(shell go list ./... 2>/dev/null | grep -v '/internal/bumblebee/')
OWN_DIRS   = $(shell go list -f '{{.Dir}}' $(OWN_PKGS))

.DEFAULT_GOAL := help

.PHONY: help build run scan-self test vet fmt fmt-check staticcheck gosec vuln lint sec ci tools clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the guardian binary
	go build -o $(BINARY) $(PKG)

run: build ## Dogfood: scan this repo with the embedded catalog, offline
	./$(BINARY) scan project --root . --no-fetch

scan-self: ## Dogfood in an isolated HOME (no writes to your real state); args pass through
	./hack/scan-self.sh

test: ## Run all tests with the race detector
	go test -race ./...

vet: ## go vet
	go vet ./...

fmt: ## Format our code (excludes the vendored tree)
	gofmt -w $(OWN_DIRS)

fmt-check: ## Fail if our code is not gofmt-clean
	@unformatted="$$(gofmt -l $(OWN_DIRS))"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed on:"; echo "$$unformatted"; exit 1; fi

staticcheck: tools ## staticcheck (our packages)
	$(GOBIN)/staticcheck $(OWN_PKGS)

gosec: tools ## gosec security scan (excludes the vendored tree)
	$(GOBIN)/gosec -quiet -exclude-dir=internal/bumblebee ./...

vuln: tools ## govulncheck (Go vulnerability database)
	$(GOBIN)/govulncheck ./...

lint: fmt-check vet staticcheck ## gofmt-check + vet + staticcheck

sec: gosec vuln ## Security scanners (gosec + govulncheck)

ci: lint sec test run ## Everything CI runs, locally

tools: ## Install dev tools (govulncheck, gosec, staticcheck) if missing
	@test -x $(GOBIN)/govulncheck || go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@test -x $(GOBIN)/gosec       || go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@test -x $(GOBIN)/staticcheck || go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

clean: ## Remove build artifacts
	rm -f $(BINARY)
