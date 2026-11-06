SHELL := /usr/bin/env bash
CARGO ?= cargo

MUSL_TARGET := x86_64-unknown-linux-musl
PREFIX      ?= /usr/local
DESTDIR     ?=

.PHONY: all build release test fmt lint audit ci \
        lab lab-down lab-check bench bench-test localhost-gate \
        syn-gate service-gate syn-service-gate \
        musl install docker man clean

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release --locked

test:
	$(CARGO) test --all-targets --all-features

fmt:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

audit:
	$(CARGO) audit

ci: fmt lint test bench-test release

# ── Phase 6 targets ───────────────────────────────────────────────────────────

## Build a fully-static musl binary (Linux only).
## Run once to add the target: rustup target add x86_64-unknown-linux-musl
## Requires musl-tools: sudo apt-get install -y musl-tools
musl:
	rustup target add $(MUSL_TARGET)
	$(CARGO) build --release --locked --target $(MUSL_TARGET)
	@echo ""
	@echo "Static binary: target/$(MUSL_TARGET)/release/rayscan"
	@file target/$(MUSL_TARGET)/release/rayscan 2>/dev/null || true

## Install rayscan to $(DESTDIR)$(PREFIX)/bin and man page to share/man/man1.
install: release
	install -Dm755 target/release/rayscan \
		$(DESTDIR)$(PREFIX)/bin/rayscan
	@if [ -f man/rayscan.1 ]; then \
		install -Dm644 man/rayscan.1 \
			$(DESTDIR)$(PREFIX)/share/man/man1/rayscan.1; \
		echo "Installed man page to $(DESTDIR)$(PREFIX)/share/man/man1/rayscan.1"; \
	fi
	@echo "Installed rayscan to $(DESTDIR)$(PREFIX)/bin/rayscan"

## Generate the man page from the CLI definition via clap_mangen.
man:
	$(CARGO) run --bin gen_man
	@echo "Man page written to man/rayscan.1"

## Build a Docker image (multi-stage, musl-based, scratch final layer).
docker:
	docker build -t rayscan:latest .
	@echo "Built rayscan:latest"

## Package release archives (.tar.gz, .zip, and SHA256SUMS).
dist: man
	@mkdir -p dist
	@rm -rf /tmp/rayscan-dist-linux /tmp/rayscan-dist-win
	@mkdir -p /tmp/rayscan-dist-linux/bin /tmp/rayscan-dist-linux/share/man/man1
	@mkdir -p /tmp/rayscan-dist-win/bin
	@cp rayscan-linux /tmp/rayscan-dist-linux/bin/
	@cp rayscan-static-musl /tmp/rayscan-dist-linux/bin/
	@cp man/rayscan.1 /tmp/rayscan-dist-linux/share/man/man1/
	@cp README.md CHANGELOG.md LICENSE /tmp/rayscan-dist-linux/
	@tar -czf dist/rayscan-0.1.0-linux-x86_64.tar.gz -C /tmp/rayscan-dist-linux .
	@cp rayscan.exe /tmp/rayscan-dist-win/bin/
	@cp README.md CHANGELOG.md LICENSE /tmp/rayscan-dist-win/
	@python3 -c "import os, zipfile; base = '/tmp/rayscan-dist-win'; zf = zipfile.ZipFile('dist/rayscan-0.1.0-windows-x86_64.zip', 'w', zipfile.ZIP_DEFLATED); [zf.write(os.path.join(r, f), os.path.relpath(os.path.join(r, f), base)) for r, _, fs in os.walk(base) for f in fs]; zf.close()"
	@cd dist && sha256sum rayscan-0.1.0-linux-x86_64.tar.gz rayscan-0.1.0-windows-x86_64.zip > SHA256SUMS
	@echo "Release archives created in dist/:"
	@cat dist/SHA256SUMS

# ── Lab / gate targets ────────────────────────────────────────────────────────

lab:
	@if [ "$$(id -u)" -eq 0 ]; then bash lab/lab.sh up; else sudo -E bash lab/lab.sh up; fi

lab-down:
	@if [ "$$(id -u)" -eq 0 ]; then bash lab/lab.sh down; else sudo -E bash lab/lab.sh down; fi

lab-check:
	@if [ "$$(id -u)" -eq 0 ]; then bash lab/lab.sh cycle; else sudo -E bash lab/lab.sh cycle; fi

bench-test:
	python3 -m unittest discover -s bench/tests -t . -v

bench:
	python3 bench/bench.py --lab

localhost-gate:
	python3 bench/localhost_gate.py

syn-gate:
	python3 bench/syn_gate.py

service-gate:
	python3 bench/service_gate.py

syn-service-gate:
	@if [ "$$(id -u)" -eq 0 ]; then python3 bench/service_gate.py --syn; else sudo -E python3 bench/service_gate.py --syn; fi

clean:
	$(CARGO) clean
	rm -rf bench/results
