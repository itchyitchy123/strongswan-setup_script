SHELL := /bin/bash

.PHONY: check lint test build integration

check: lint test

lint:
	gofmt -d main.go main_test.go | (! grep .)
	CGO_ENABLED=0 go vet -p 1 ./...

test:
	CGO_ENABLED=0 go test -p 1 ./...

build:
	CGO_ENABLED=0 go build -o bin/strongswan-setup .

integration: build
	docker build -f tests/integration/Dockerfile -t strongswan-setup-integration .
	docker run --rm --cap-add=NET_ADMIN strongswan-setup-integration
