## Linked Issue

Fixes #

## Summary

-

## Required Format

- Branch name uses an approved prefix: `feat/`, `fix/`, `docs/`, `test/`, `refactor/`, `perf/`, `security/`, `chore/`, `ci/`, `build/`, `release/`, or `revert/`.
- PR title uses Conventional Commit style, for example `fix(backup): validate restore checkpoints`.
- Commit messages use Conventional Commits.

## Scope

- [ ] This PR solves one issue or one clearly scoped maintenance task.
- [ ] This PR does not include unrelated formatting, experiments, generated files, local data, keys, logs, backups, or build artifacts.
- [ ] User-facing documentation describes implemented behavior only.

## Proof, Storage, And Compatibility

- [ ] No L1/L2/L3/L4/L5 semantic change.
- [ ] L4/L5 behavior is unchanged: L4 is batch root in Global Log; L5 is STH/global root externally anchored.
- [ ] `.tdclaim`, `.tdproof`, `.tdgproof`, `.tdanchor-result`, `.sproof`, and `.tdbackup` formats are unchanged.
- [ ] WAL, proofstore, global log, anchor outbox, backup, and desktop local storage durable boundaries are unchanged.
- [ ] No production path introduces full-scan, full-load, full-sort, or full-recompute behavior.

If any box above is false, explain the compatibility, migration, recovery, or verification impact:

-

## Validation

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] `go test -tags=integration ./...`
- [ ] `go test -tags=e2e ./...`
- [ ] `cd clients/web && npm ci && npm run build`
- [ ] `cd website && npm ci && npm run build`
- [ ] `cd clients/desktop && go test ./...`
- [ ] `cd clients/desktop && go test -race ./...`

Checks not run:

-

## Risk And Rollback

-
