.PHONY: run tidy test build

run:
	go run ./cmd

tidy:
	go mod tidy

test:
	go test ./...

build:
	go build -o bin/auth ./cmd
