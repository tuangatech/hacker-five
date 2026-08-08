.PHONY: build test lint fuzz integration

build:
	go build -o hackerfive ./cmd/hackerfive

test:
	go test -race ./...

lint:
	golangci-lint run ./...

fuzz:
	go test -fuzz=FuzzResponseParsing -fuzztime=30s ./pkg/scanner/httpclient/

integration:
	go test -tags=integration ./tests/integration/... -v
