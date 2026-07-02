# Merkle — GNU Makefile
#
# Replaces the former `justfile` (see git history). Self-documenting: run
# `make` or `make help` to list every target. Targets are grouped under
# `##@ Section` headers; each target's `## comment` is the help text.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-builtin-rules --no-print-directory
.DELETE_ON_ERROR:

# ------------------------------------------------------------------------------
# Variables (override via `make VAR=value target` or the environment)
# ------------------------------------------------------------------------------
CARGO   ?= cargo
SPEC    ?= $(HOME)/bin/spec
ARGS    ?=

# Deploy / signing (this machine's real deployment playbook — see project
# CLAUDE.md "Deployment & signing" section for the full narrative).
SIGN_ID                    ?= Apple Development: Fabricio Fonseca (J3LVNXCU3U)
PREFIX                     ?= /usr/local/bin
BINS                       := merkle merkle-agent merkle-mcp
LAUNCHD_LABEL              := dev.fapp.merkle.agent
LAUNCHD_PLIST              := deploy/launchd/dev.fapp.merkle.agent.plist
LAUNCHD_WRAPPER            := deploy/launchd/merkle-agent-launchd
LAUNCHD_WRAPPER_INSTALLED  := $(PREFIX)/merkle-agent-launchd
LAUNCHAGENTS_DIR           := $(HOME)/Library/LaunchAgents
LOGS_DIR                   := $(HOME)/Library/Logs
MERKLE_RECOVERY_RECIPIENT  ?=

# ------------------------------------------------------------------------------
##@ Help
# ------------------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

# ------------------------------------------------------------------------------
##@ Build
# ------------------------------------------------------------------------------

.PHONY: build check build-release
build: ## Build all workspace crates (debug)
	$(CARGO) build --workspace

check: ## Check all workspace crates and targets without producing binaries
	$(CARGO) check --workspace --all-targets

build-release: ## Build all workspace crates in release mode
	$(CARGO) build --release --workspace

# ------------------------------------------------------------------------------
##@ Test
# ------------------------------------------------------------------------------

.PHONY: test test-fast test-doc
test: ## Run all workspace tests (lib + bins + doc tests)
	$(CARGO) test --workspace

test-fast: ## Run lib and bin tests only (faster, skips doc tests)
	$(CARGO) test --workspace --lib --bins

test-doc: ## Run doc tests only
	$(CARGO) test --workspace --doc

# ------------------------------------------------------------------------------
##@ Code quality
# ------------------------------------------------------------------------------

.PHONY: lint fmt fmt-check
lint: ## Run Clippy with -D warnings (mirrors CI)
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt: ## Format all sources in-place
	$(CARGO) fmt --all

fmt-check: ## Check formatting without modifying files (mirrors CI)
	$(CARGO) fmt --check --all

# ------------------------------------------------------------------------------
##@ Security
# ------------------------------------------------------------------------------

.PHONY: deny audit
deny: ## Run cargo-deny license + bans + advisory + sources checks
	$(CARGO) deny check

audit: ## Run cargo-audit advisory check against the RustSec DB
	$(CARGO) audit

# ------------------------------------------------------------------------------
##@ Coverage
# ------------------------------------------------------------------------------

.PHONY: cov cov-lcov
cov: ## Generate an HTML coverage report
	$(CARGO) llvm-cov --workspace --html
	@echo "Coverage report: target/llvm-cov/html/index.html"

cov-lcov: ## Generate an LCOV coverage report (for CI artifact upload)
	$(CARGO) llvm-cov --workspace --lcov --output-path coverage.lcov

# ------------------------------------------------------------------------------
##@ Benchmarks
# ------------------------------------------------------------------------------

.PHONY: bench
bench: ## Run all workspace benchmarks
	$(CARGO) bench --workspace

# ------------------------------------------------------------------------------
##@ Spec validation (ADR-0018)
# ------------------------------------------------------------------------------

.PHONY: spec spec-fast spec-medium
spec: ## Run the full spec validation lane — all 14 validators (CI gate)
	$(SPEC) validate --lane full

spec-fast: ## Run the fast spec validation lane (~1.5s)
	$(SPEC) validate --lane fast

spec-medium: ## Run the medium spec validation lane (~10s, default) — must stay 9/9 green
	$(SPEC) validate

# ------------------------------------------------------------------------------
##@ Doctor
# ------------------------------------------------------------------------------

# NOTE: `doctor` intentionally does NOT run the spec lanes — it is the
# check+clippy+test one-shot local gate. Use `doctor-full` to also run the
# full spec lane in one shot (equivalent to the CI merge gate).
.PHONY: doctor doctor-full
doctor: check lint test ## One-shot health gate: check + clippy + test (no spec lane)

doctor-full: doctor spec ## doctor + full spec validation lane (CI-equivalent gate)

# ------------------------------------------------------------------------------
##@ Run
# ------------------------------------------------------------------------------

.PHONY: agent cli
agent: ## Start the Vault Agent daemon (dev mode)
	$(CARGO) run -p merkle-agent --

cli: ## Run the Merkle CLI (pass args: make cli ARGS="status")
	$(CARGO) run -p merkle-cli -- $(ARGS)

# ------------------------------------------------------------------------------
##@ Release
# ------------------------------------------------------------------------------

.PHONY: release-dry
release-dry: build-release deny audit ## Release dry-run: release build + deny + audit (no publish)

# ------------------------------------------------------------------------------
##@ Clean
# ------------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts and the spec report cache
	$(CARGO) clean
	rm -rf .spec-reports docs/arch/formal/states

# ------------------------------------------------------------------------------
##@ Deploy & signing (macOS only)
# ------------------------------------------------------------------------------
#
# Real deployment playbook for this machine. Signing identity is the only
# codesigning cert present (`security find-identity -v -p codesigning`) — an
# "Apple Development" cert, not a "Developer ID Application" cert. The
# verification gate is `codesign --verify --deep --strict --verbose=2` (exit
# 0); `spctl --assess` reports "rejected" for Apple-Development-signed
# binaries and that is expected — Gatekeeper only gates downloaded/quarantined
# files, so spctl is NEVER the gate here.

ifeq ($(shell uname),Darwin)

.PHONY: sign verify-sign install install-wrapper kickstart deploy redeploy restart \
	launchd-install launchd-bootout launchd-status logs doctor-live

sign: ## Codesign the three release binaries in target/release/ and verify each
	@for bin in $(BINS); do \
		echo "==> signing target/release/$$bin"; \
		codesign --force --options runtime --timestamp --sign "$(SIGN_ID)" "target/release/$$bin"; \
		codesign --verify --deep --strict --verbose=2 "target/release/$$bin"; \
	done

verify-sign: ## Verify the installed $(PREFIX) copies (authoritative post-install gate)
	@for bin in $(BINS); do \
		codesign --verify --deep --strict --verbose=2 "$(PREFIX)/$$bin"; \
	done

install: sign ## Install signed binaries to $(PREFIX) (sudo) and re-verify
	@for bin in $(BINS); do \
		echo "==> installing $$bin to $(PREFIX)"; \
		sudo install -m 755 -o root -g wheel "target/release/$$bin" "$(PREFIX)/$$bin"; \
		sudo codesign --force --options runtime --timestamp --sign "$(SIGN_ID)" "$(PREFIX)/$$bin" || true; \
		codesign --verify --deep --strict --verbose=2 "$(PREFIX)/$$bin"; \
	done
	# The `sudo codesign` re-sign of the installed copy may print
	# errSecInternalComponent — non-fatal (root has no access to the login
	# keychain). The target/ signature survives `install` on APFS->APFS, so
	# `|| true` there and treat the `codesign --verify` line above as the
	# authoritative, must-exit-0 gate.

install-wrapper: ## Install deploy/launchd/merkle-agent-launchd, injecting MERKLE_RECOVERY_RECIPIENT
	@recipient="$(MERKLE_RECOVERY_RECIPIENT)"; \
	if [ -z "$$recipient" ]; then \
		recipient="$$(grep -o 'age1[a-z0-9]*' '$(LAUNCHD_WRAPPER_INSTALLED)' 2>/dev/null | head -1 || true)"; \
	fi; \
	if [ -z "$$recipient" ]; then \
		echo "error: no MERKLE_RECOVERY_RECIPIENT given and none found in the installed $(LAUNCHD_WRAPPER_INSTALLED)" >&2; \
		echo "       pass it explicitly: make install-wrapper MERKLE_RECOVERY_RECIPIENT=age1..." >&2; \
		exit 1; \
	fi; \
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	rendered="$$tmpdir/merkle-agent-launchd"; \
	awk -v recipient="$$recipient" '/^exec \/usr\/local\/bin\/merkle-agent$$/ { print "export MERKLE_RECOVERY_RECIPIENT=\"" recipient "\""; print "" } { print }' '$(LAUNCHD_WRAPPER)' > "$$rendered"; \
	sh -n "$$rendered"; \
	sudo install -m 755 -o root -g wheel "$$rendered" "$(LAUNCHD_WRAPPER_INSTALLED)"; \
	echo "installed $(LAUNCHD_WRAPPER_INSTALLED) with MERKLE_RECOVERY_RECIPIENT injected"

kickstart: ## Restart the LaunchAgent with the currently installed binary
	launchctl kickstart -k gui/$$(id -u)/$(LAUNCHD_LABEL)
	sleep 2
	$(PREFIX)/merkle status

deploy: build-release sign install kickstart ## One-shot release deploy: build, sign, install, kickstart

redeploy: kickstart ## Alias for kickstart (binary already installed)

restart: kickstart ## Restart the launchd agent (alias for kickstart)

launchd-install: ## Render the plist (REPLACE_WITH_USER -> $$USER) and bootstrap the LaunchAgent
	mkdir -p $(LAUNCHAGENTS_DIR) $(LOGS_DIR)
	sed "s|REPLACE_WITH_USER|$$USER|g" $(LAUNCHD_PLIST) > $(LAUNCHAGENTS_DIR)/$(LAUNCHD_LABEL).plist
	launchctl bootstrap gui/$$(id -u) $(LAUNCHAGENTS_DIR)/$(LAUNCHD_LABEL).plist

launchd-bootout: ## Unload the LaunchAgent
	launchctl bootout gui/$$(id -u)/$(LAUNCHD_LABEL)

launchd-status: ## Print LaunchAgent state / pid / last exit
	launchctl print gui/$$(id -u)/$(LAUNCHD_LABEL) | grep -E "state|pid|last exit"

logs: ## Tail the last 40 lines of the agent's stdout/stderr logs
	tail -n 40 $(LOGS_DIR)/merkle-agent.out.log $(LOGS_DIR)/merkle-agent.err.log

doctor-live: ## Run `merkle doctor` against the installed, running daemon
	$(PREFIX)/merkle doctor

else

.PHONY: sign verify-sign install install-wrapper kickstart deploy redeploy \
	launchd-install launchd-bootout launchd-status logs doctor-live
sign verify-sign install install-wrapper kickstart deploy redeploy \
launchd-install launchd-bootout launchd-status logs doctor-live:
	@echo "error: '$@' is a macOS-only target (codesign / launchd); current platform is $(shell uname)" >&2
	@exit 1

endif
