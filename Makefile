.PHONY: build test fmt vet check web-install web-build

CARGO ?= cargo
NPM ?= npm

build:
	$(CARGO) build --workspace --locked

test:
	$(CARGO) test --workspace --locked

fmt:
	$(CARGO) fmt --all

vet:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) build --workspace --locked
	$(CARGO) test --workspace --locked
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

web-install:
	$(NPM) --prefix web ci

web-build:
	$(NPM) --prefix web run build
