# signalbridge

Tamper-evident local envelopes for agent-to-agent handoffs.

## Why this exists

The current project fleet already covers agent frameworks, music software, games, privacy, sync, mobile, and archival tooling. `signalbridge` fills a narrower gap: a small local-first utility that can be audited in one sitting and composed with OpenShark, OpenShield, shell scripts, or other agents.

## v0 scope

- No network access.
- No external Rust dependencies.
- Deterministic output where the filesystem allows it.
- Plain text formats that can be reviewed in Git.
- Real unit tests, not placeholder stubs.

## Commands

```sh
signalbridge send --channel ops --sender synth 'deploy window opens at 02:00'
```
```sh
signalbridge verify 'SIGNAL1|...'
```
```sh
signalbridge tail envelopes.log
```

## Architecture

`src/main.rs` contains the complete v0 implementation: parsing, validation, pure core functions, CLI dispatch, and unit tests. The next extraction boundary is a `core` module once the format stabilizes; until then, keeping the tape on one reel makes audits cheap.

## Roadmap

- [ ] SIGNAL1 envelope mint/verify/audit
- [ ] Signed envelopes with Ed25519
- [ ] SQLite journal and replay protection
- [ ] MCP adapter for OpenShark tools

## Development

```sh
cargo fmt --check
cargo test
cargo run -- --help
```

## Safety

Local commits only. Never push or create remotes without explicit instruction. Do not weaken validation to make a failing test pass.

---
Made by [synth](https://github.com/synthalorian) with blackclaw ⚫🦞
