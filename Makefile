BINARY=apiping
VERSION ?= dev
OUTPUT_DIR=dist

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null || echo $(VERSION))

LDFLAGS=-ldflags "-X main.Version=$(GIT_TAG) -X main.Commit=$(GIT_COMMIT)"

all: build

help:
    @echo "Available make targets:"
    @echo "  build       - Build apiping binary for current platform"
    @echo "  xbuild      - Build apiping binaries for all platforms"
    @echo "  clean       - Remove all build artifacts"
    @echo "  test        - Run unit tests"
    @echo "  fmt         - Format Go code"
    @echo "  lint        - Run linter"
    @echo "  release     - Prepare release (use with GitHub Actions)"

build:
    @echo "Building apiping for $(GOOS)/$(GOARCH)"
    @go build -o $(BINARY) $(LDFLAGS) .

xbuild:
    @mkdir -p $(OUTPUT_DIR)
    @echo "Building apiping for multiple platforms..."
    @for osarch in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
        GOOS=$${osarch%/*} \
        GOARCH=$${osarch##*/} \
        BINARY_NAME=$(BINARY)-$(GIT_TAG)-$$GOOS-$$GOARCH ; \
        if [ "$$GOOS" = "windows" ]; then \
            BINARY_NAME=$$BINARY_NAME.exe ; \
        fi ; \
        echo "Building $$GOOS/$$GOARCH -> $$BINARY_NAME" ; \
        CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -o $(OUTPUT_DIR)/$$BINARY_NAME $(LDFLAGS) . ; \
    done
    @echo "Done. Binaries are in $(OUTPUT_DIR)/"

clean:
    @echo "Cleaning build artifacts..."
    @rm -f $(BINARY)
    @rm -rf $(OUTPUT_DIR)/*

test:
    @echo "Running tests..."
    @go test -v ./...

fmt:
    @echo "Formatting Go code..."
    @go fmt ./...

lint:
    @echo "Running golangci-lint..."
    @if ! command -v golangci-lint &> /dev/null; then \
        echo "Error: golangci-lint is not installed." ; \
        exit 1 ; \
    fi
    @golangci-lint run

release:
    @echo "Release handled via GitHub Actions on tag push."
    @echo "To create a new release:"
    @echo "  git tag v1.0.0"
    @echo "  git push origin v1.0.0"