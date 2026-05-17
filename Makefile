.PHONY: build test lint fmt vet clean

BIN := bin/dredge

build:
	go build -o $(BIN) ./cmd/dredge

test:
	go test ./...

test-integration:
	go test -tags integration ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf bin/
