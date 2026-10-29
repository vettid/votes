# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

`votes.vettid.org`: a write-once public store of ballot documents
(BALLOT-PROTOCOL §3.3), with an upload API that verifies each document
and its Rekor anchor. The design is
[docs/VOTES-SITE.md](docs/VOTES-SITE.md). It holds no signing keys, no
member data and no sessions, and keeps no record of readers.

## Conventions

- Go, standard library first (`net/http`, `log/slog`). No frameworks.
  Sigstore verification uses `sigstore-go` at a pinned version.
- Infrastructure is CDK (TypeScript) under `cdk/`, as member-service.
- Logs carry ids, types, sizes and error codes, never client addresses
  or document contents.

## Coordination rules

1. **Scope.** Work in this repository. Read service-vault, vettid-vault,
   vettid-relay and vettid.org; open PRs there only when the owner
   assigns them.
2. **Small PRs**, each with its tests passing locally before it is
   pushed. The owner merges.
3. **Public text** (commits, PRs, issues, code comments) never mentions
   reviews, finding ids, private files or local paths outside the
   repository. Cite specifications by document and section.
4. **No secrets in the repository.** Test keys only from fixed, public
   test seeds; gitleaks runs in CI.
5. **Commit trailers and PR bodies**: as the harness provides them; no
   other attribution.
