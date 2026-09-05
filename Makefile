SHELL := /bin/bash

.PHONY: check lint test build

check: lint test

lint:
	gofmt -d main.go main_test.go | (! grep .)
	CGO_ENABLED=0 go vet -p 1 ./...

test:
	CGO_ENABLED=0 go test -p 1 ./...

build:
	CGO_ENABLED=0 go build -o bin/strongswan-setup .
