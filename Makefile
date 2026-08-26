SHELL := /bin/bash

.PHONY: check lint test syntax

check: lint syntax test

lint:
	shellcheck install-strongswan.sh tests/run.sh

syntax:
	bash -n install-strongswan.sh tests/run.sh

test:
	bash tests/run.sh
