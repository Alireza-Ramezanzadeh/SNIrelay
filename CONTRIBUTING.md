# Contributing to SNIrelay

Thanks for helping improve SNIrelay. This document explains how we work and what we expect from contributions.

## Code of conduct

Be respectful and constructive. Assume good intent. Disagreement about design is normal; personal attacks are not.

## Ways to contribute

- **Bug reports** — Include version (`snirelay --version` or image tag), OS/Docker setup, minimal config (redact secrets), and logs.
- **Feature ideas** — Open an issue first for larger changes so we can align on scope and compatibility.
- **Pull requests** — Prefer small, focused PRs with a clear description and test evidence.

## Development setup

### Requirements

- **Rust 1.85+** (see `rust-version` / `Dockerfile` if we pin one explicitly).
- **Linux** is the primary target; patches for other platforms are welcome if they stay maintainable.

### Clone and build

```bash
git clone https://github.com/Alireza-Ramezanzadeh/SNIrelay.git
cd SNIrelay

cargo build
cargo test
```

### Before you open a PR

Run these locally; CI may not exist yet, so this keeps `main` healthy:

```bash
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test
```

Fix any new warnings from `clippy` unless there is a strong reason to suppress them (then document why in the PR).

## Project layout

| Path | Role |
|------|------|
| `src/main.rs` | CLI entry, wiring |
| `src/service.rs` | Listeners, connection handling, splice |
| `src/sni.rs` | TLS ClientHello / SNI parsing |
| `src/proxy_connector.rs` | SOCKS5 / HTTP CONNECT upstream |
| `src/config.rs` | YAML + env config |
| `src/metrics.rs` | Prometheus registration and scrape snapshot |
| `src/hosts.rs` | Static hosts table |
| `src/limits.rs` | `RLIMIT_NOFILE` and connection cap helpers |
| `config/config.yaml` | Example configuration |
| `grafana/` | Dashboard JSON + `gen_dashboard.py` |

## Coding guidelines

- **Match existing style** — Imports, error handling (`anyhow::Context`), and `tracing` usage should look like the surrounding code.
- **Keep hot paths lean** — Avoid extra allocations or blocking work on the Tokio runtime in per-connection paths. Heavy work belongs on `spawn_blocking` or background tasks (see metrics snapshot pattern).
- **TLS passthrough** — Do not add TLS termination in the default path. Changes that parse more of the handshake must preserve correct replay to the upstream.
- **Compatibility** — Prometheus metrics intentionally keep the `sniproxy_*` prefix and label sets for existing dashboards. If you rename or remove a metric, document it in the PR and update `grafana/gen_dashboard.py` + `README.md` as needed.
- **Config** — Routing is **`hosts` only**; do not add per-listener `routes` (ignored with a warning). See [`config/config.limoo.yaml`](config/config.limoo.yaml) for a production-style example.

## Configuration and docs

- If you add or rename YAML fields, update `config/config.yaml` (comments + examples) and any README sections that list options.
- If Docker behavior changes, update `Dockerfile` and `docker-entrypoint.sh`.

## Grafana dashboard

The checked-in dashboard is generated from Python:

```bash
python3 grafana/gen_dashboard.py
```

Commit both `grafana/gen_dashboard.py` and `grafana/dashboards/sniproxy-overview.json` when you change queries or layout.

## Commits and pull requests

- **Commits** — Use clear, imperative subjects (e.g. `Fix HTTP header timeout on slow clients`). Multiple commits per PR are fine; we can squash on merge if the repo default prefers it.
- **PR description** — What changed, why, and how you tested (unit tests, manual curl, Docker smoke test, etc.).
- **No secrets** — Never commit API keys, real hostnames you must keep private, or `.env` files. Use placeholders in examples.

## Security issues

If you find a security-sensitive bug (e.g. protocol abuse, memory safety, remote crash), please report privately to the maintainers (GitHub Security Advisories or email listed on the maintainer profile) instead of a public issue, where practical.

## License

By contributing, you agree your contributions are licensed under the same terms as the project ([MIT](LICENSE)).
