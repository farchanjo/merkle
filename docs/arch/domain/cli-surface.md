# CLI Surface — Merkle

## Purpose

Operator CLI over the Companion Socket.

## Overview

merkle never opens keystore or SQLite; all work is socket-backed.

## Binary

bin/merkle-cli installs as merkle.

## Command groups

init, unseal, seal, status, doctor, bind, put, list, get, describe, search,
rotate, rollback, delete, reveal, audit, backup, restore, device,
verify-recovery-key.

## Stable Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime failure |
| 2 | Usage error |
| 3 | Policy denied |
| 4 | Not found |
| 5 | Infrastructure error |

## --json Contract

When --json is supported: single JSON object on stdout; non-zero exit codes
from Stable Exit Codes; no secret plaintext except explicit reveal commands.

## Invariants

Same-UID peer-cred; operator confirmation for sensitive paths; no secret logs.

## Observability

merkle doctor and agent metrics.

## Schema contracts

[schema index](../schemas/README.md).
