.PHONY: run tidy test docker-up docker-down

ifneq (,$(wildcard ./.env))
include .env
export
endif

run:
	go run ./cmd

tidy:
	go mod tidy

test:
	go test ./...

dcup:
	docker compose up -d --build

dcdown:
	docker compose down -v
