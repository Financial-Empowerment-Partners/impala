# =============================================================================
# lumencli — build & verification
#
# Targets:
#   build         Build ./lumencli for the host platform (static, version-stamped)
#   test          go test ./...
#   race          go test -race ./...
#   vet           go vet ./...
#   fmt-check     Fail, listing the files, if anything is not gofmt-formatted
#   vulncheck     govulncheck (needs network; deliberately not part of 'verify')
#   cross         Cross-build all six release targets into $(DIST)/
#   verify        fmt-check + vet + test + race + build (host only, no network)
#   verify-linux  Run the test suite in Docker for linux/arm64 AND linux/amd64
#                 (on macOS this rides OrbStack), then smoke-test any
#                 cross-built linux binaries found in $(DIST)/
#   verify-all    verify + verify-linux + vulncheck
#   clean         Remove $(DIST)/ and the local ./lumencli binary
#
# GNU Make 3.81 compatible; recipes are POSIX sh.
# =============================================================================

GO ?= go

# Docker image for the Linux verification legs. Pinned to the Debian
# (bookworm) variant: alpine images are musl-based and cannot run the Go race
# detector. Every container also sets GOTOOLCHAIN=local so that an image whose
# Go is older than go.mod's requirement fails loudly instead of silently
# downloading a newer toolchain inside the container.
GOIMAGE ?= golang:1.26-bookworm

VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X lumencli/internal/cli.version=$(VERSION) -X lumencli/internal/stellar.appVersion=$(VERSION)
DIST    ?= dist

# Repo root (this Makefile lives in <repo>/lumencli); bind-mounted into the
# verification containers at /src.
REPO := $(abspath $(CURDIR)/..)

# Shared docker-run flags for verify-linux. GOFLAGS=-buildvcs=false because
# the bind-mounted repo trips git's safe.directory check inside the container;
# the module cache is shared across arches (it is arch-independent), while the
# build cache is per-arch.
DOCKER_COMMON = --rm \
	-v lumencli-gomod:/go/pkg/mod \
	-v $(REPO):/src \
	-w /src/lumencli \
	-e GOFLAGS=-buildvcs=false \
	-e GOTOOLCHAIN=local

.PHONY: build test race vet fmt-check vulncheck cross verify verify-linux verify-all clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o lumencli .

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "fmt-check: the following files are not gofmt-formatted:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi

# govulncheck downloads the vulnerability database, so it needs network access
# and is therefore not part of plain 'verify'. Pinned version.
vulncheck:
	sh scripts/vulncheck.sh

cross:
	@mkdir -p $(DIST); \
	for os in darwin linux windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ]; then ext=".exe"; else ext=""; fi; \
			out="$(DIST)/lumencli_$(VERSION)_$${os}_$${arch}$$ext"; \
			echo "building $$out"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
				$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$$out" . || exit 1; \
		done; \
	done

verify: fmt-check vet test race build

# Every docker run below passes --platform explicitly: a bare image tag
# silently resolves to whichever architecture was pulled last, so a run could
# otherwise quietly test the wrong arch.
#
# The linux/amd64 leg is Rosetta-emulated on Apple Silicon, and the Go race
# detector is unsupported under emulation — that leg runs plain 'go test'.
verify-linux:
	docker run --platform linux/arm64 $(DOCKER_COMMON) \
		-v lumencli-gocache-arm64:/root/.cache/go-build \
		$(GOIMAGE) go test -race ./...
	docker run --platform linux/amd64 $(DOCKER_COMMON) \
		-v lumencli-gocache-amd64:/root/.cache/go-build \
		$(GOIMAGE) go test ./...
	@for arch in arm64 amd64; do \
		bin="$(DIST)/lumencli_$(VERSION)_linux_$$arch"; \
		if [ -x "$$bin" ]; then \
			echo "smoke: running $$bin on linux/$$arch"; \
			docker run --platform linux/$$arch $(DOCKER_COMMON) $(GOIMAGE) \
				sh -c "./$$bin version && ./$$bin account new" || exit 1; \
		else \
			echo "smoke: $$bin not found — run 'make cross' first (skipping)"; \
		fi; \
	done

verify-all: verify verify-linux vulncheck

clean:
	rm -rf $(DIST) ./lumencli
