# LAN Sentinel build. LAN Sentinel is Linux only: the deliverables are static
# linux/amd64 and linux/arm64 binaries (CGO_ENABLED=0), and every Go command
# below (build, vet, lint, vuln, test, fuzz, release) runs in the Linux dev
# container (build/dev.Dockerfile), on any host with Docker.
BIN      := lan-sentinel
PKG      := lan-sentinel
PKGS     ?= ./...
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# The commit's time, not the build's: the same commit builds the same bytes.
DATE     ?= $(shell TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
LDFLAGS  := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)
COVERAGE := coverage.out
TEST_BIN := .build/test
# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 30s
# Minimum coverage of internal/ in percent (make coverage, make check).
COVER_MIN ?= 90

# Dev container: the image tag follows the Dockerfile's content, caches live on
# a named volume, and commands run as the calling user so files in the
# checkout stay yours.
DEV_IMAGE := lan-sentinel-dev:$(shell git hash-object build/dev.Dockerfile 2>/dev/null | cut -c1-12)
CACHE_VOL := lan-sentinel-cache
USER_ID   := $(shell id -u):$(shell id -g)
RUN       := docker run --rm -v "$(CURDIR)":/src -w /src -v $(CACHE_VOL):/cache --user $(USER_ID) \
	-e LDFLAGS="$(LDFLAGS)" -e FUZZTIME=$(FUZZTIME) -e VERSION=$(VERSION) -e SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(DEV_IMAGE)

.DEFAULT_GOAL := help
.PHONY: help all dev-image shell build release tools package oui fixtures fmt fmt-check tidy tidy-check mod-verify vet lint vuln \
	test coverage cover fuzz soak test-net test-systemd check check-all run-dev clean clean-cache

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check build ## Run check, then build

# --- dev container -----------------------------------------------------------

dev-image: ## Build the Linux dev image (Go toolchain, golangci-lint) and the cache volume
	@docker image inspect $(DEV_IMAGE) >/dev/null 2>&1 || { \
		echo "Building $(DEV_IMAGE)"; docker build -q -t $(DEV_IMAGE) -f build/dev.Dockerfile build >/dev/null; }
	@docker volume inspect $(CACHE_VOL) >/dev/null 2>&1 || { \
		docker volume create $(CACHE_VOL) >/dev/null && \
		docker run --rm -v $(CACHE_VOL):/cache --user 0 $(DEV_IMAGE) chown $(USER_ID) /cache; }

shell: dev-image ## Open a shell in the dev container
	@docker run --rm -it -v "$(CURDIR)":/src -w /src -v $(CACHE_VOL):/cache --user $(USER_ID) $(DEV_IMAGE) bash

# --- build -------------------------------------------------------------------

build: dev-image ## Build bin/lan-sentinel for the Docker host's architecture
	@echo "Building bin/$(BIN) ($(VERSION))"
	@$(RUN) go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/$(BIN)

release: dev-image ## Static linux/amd64 and linux/arm64 binaries into dist/ with SHA256SUMS
	@$(RUN) build/release.sh release

tools: dev-image ## capcheck for linux/amd64 and linux/arm64 into dist/tools/ (privilege check)
	@$(RUN) build/release.sh tools

package: release tools ## Release tarballs per target into dist/release/ with SHA256SUMS (VERSION=vX.Y.Z)
	@$(RUN) build/release.sh package

oui: dev-image ## Regenerate data/oui/oui.tsv.gz and oui.bin from the IEEE registries (each release)
	@$(RUN) go run ./data/oui/gen -out data/oui/oui.tsv.gz -bin data/oui/oui.bin

fixtures: dev-image ## Regenerate the synthetic pcap fixtures in test/fixtures
	@$(RUN) go run ./test/fixtures/gen -dir test/fixtures

# --- hygiene -----------------------------------------------------------------

fmt: dev-image ## Format Go code with gofmt -s
	@echo "Running gofmt"
	@$(RUN) gofmt -s -w .

fmt-check: dev-image ## Fail if any Go file is not gofmt -s formatted
	@echo "Checking gofmt"
	@$(RUN) sh -c 'out=$$(gofmt -s -l .); if [ -n "$$out" ]; then echo "Not formatted (run make fmt):"; echo "$$out"; exit 1; fi'

tidy: dev-image ## Tidy go.mod and go.sum
	@echo "Running go mod tidy"
	@$(RUN) go mod tidy

tidy-check: dev-image ## Fail if go.mod or go.sum is not tidy
	@echo "Checking go mod tidy"
	@$(RUN) go mod tidy -diff

mod-verify: dev-image ## Verify downloaded modules against go.sum
	@echo "Running go mod verify"
	@$(RUN) go mod verify

vet: dev-image ## Run go vet
	@echo "Running go vet on $(PKGS)"
	@$(RUN) go vet $(PKGS)

lint: dev-image ## Run golangci-lint (includes staticcheck), including the nettest-tagged tests
	@echo "Running golangci-lint"
	@$(RUN) golangci-lint run --build-tags nettest $(PKGS)

vuln: dev-image ## Run govulncheck (pinned as a tool in go.mod)
	@echo "Running govulncheck"
	@$(RUN) go tool govulncheck $(PKGS)

# --- tests -------------------------------------------------------------------

# The race detector needs cgo; the code under test stays cgo-free.
test: dev-image ## Unit and golden tests with the race detector
	@echo "Running tests on $(PKGS)"
	@$(RUN) env CGO_ENABLED=1 go test -race $(PKGS)

# Coverage of internal/ from every test package; fails below COVER_MIN
# (build/coverage.sh says what is counted).
coverage: dev-image ## Tests with race detector and coverage of internal/ (fails below COVER_MIN, default 90%)
	@echo "Running tests with coverage of internal/ (minimum $(COVER_MIN)%)"
	@$(RUN) env COVER_MIN=$(COVER_MIN) COVERAGE=$(COVERAGE) build/coverage.sh

cover: coverage ## Write coverage.html and open it in a browser
	@$(RUN) go tool cover -html=$(COVERAGE) -o coverage.html
	@echo "Opening coverage.html"
	@open coverage.html 2>/dev/null || xdg-open coverage.html 2>/dev/null || echo "Open coverage.html in a browser"

fuzz: dev-image ## Run every Fuzz* target back to back for FUZZTIME each (default 30s)
	@$(RUN) build/fuzz.sh

soak: dev-image ## 90 simulated days of a 50-host LAN: database size, retention, heap and CPU (several minutes)
	@$(RUN) go test -tags soak -run TestNinetyDays -v -timeout 60m ./test/soak/

test-net: dev-image ## Network integration tests in Docker on a test network (CAP_NET_RAW only)
	@$(RUN) build/test-bins.sh $(TEST_BIN)
	@BIN_DIR=$(TEST_BIN) test/net/run.sh

test-systemd: dev-image ## The daemon under systemd in a container with the deploy/ unit files
	@$(RUN) build/test-bins.sh $(TEST_BIN)
	@BIN_DIR=$(TEST_BIN) test/systemd/run.sh

# --- gates -------------------------------------------------------------------

check: fmt-check tidy-check vet lint vuln coverage ## Fast gate: format, tidy, vet, lint, vuln, tests with coverage

check-all: check test-net test-systemd ## check plus the Docker network and systemd suites

# --- run and clean -----------------------------------------------------------

run-dev: dev-image ## Run the daemon in the dev container on the replay dev config
	@docker run --rm -it --init -v "$(CURDIR)":/src -w /src -v $(CACHE_VOL):/cache --user $(USER_ID) \
		$(DEV_IMAGE) go run ./cmd/$(BIN) daemon run --config deploy/config.dev.yaml

clean: ## Remove bin/, dist/, dev/, .build/ and coverage output
	@echo "Cleaning up"
	@rm -rf bin dist dev .build $(COVERAGE) coverage.html

clean-cache: ## Remove the dev container cache volume
	@docker volume rm $(CACHE_VOL) >/dev/null 2>&1 || true
