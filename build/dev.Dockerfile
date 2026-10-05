# Linux development image. Every make target that runs Go runs in here, as
# the calling user, with caches on the lan-sentinel-cache volume (/cache).
FROM golang:1.27-bookworm

ARG GOLANGCI_LINT_VERSION=v2.14.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends file \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
       | sh -s -- -b /usr/local/bin "${GOLANGCI_LINT_VERSION}"

# Version metadata is stamped with -ldflags, so VCS stamping is off (the
# mounted checkout may be owned by another uid).
ENV HOME=/tmp \
    GOCACHE=/cache/go-build \
    GOMODCACHE=/cache/mod \
    GOLANGCI_LINT_CACHE=/cache/golangci-lint \
    GOFLAGS=-buildvcs=false \
    CGO_ENABLED=0
WORKDIR /src
