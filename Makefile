.PHONY: build test test-integration test-all lint fmt vet clean install help

BIN     := bin/dredge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BIN) ./cmd/dredge

test:
	go test ./...

test-integration:
	go test -tags integration -v ./test/...

test-all: test test-integration

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf bin/

install: build
	cp $(BIN) /usr/local/bin/dredge

help:
	@echo "Targets:"
	@echo "  build             Build binary to bin/dredge"
	@echo "  test              Run unit tests"
	@echo "  test-integration  Run integration tests (requires Docker)"
	@echo "  test-all          Run unit + integration tests"
	@echo "  lint              Run golangci-lint"
	@echo "  fmt               Format Go code with gofmt"
	@echo "  vet               Run go vet"
	@echo "  clean             Remove build artifacts"
	@echo "  install           Install to /usr/local/bin"
