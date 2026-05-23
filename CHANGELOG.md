# Changelog

All notable changes to **SNIrelay** are documented in this file.

## [0.2.2] — 2026-05-23

Production release: **hosts-only** routing, persistent domain limits, file logging, and **snirelay** branding.

### Added

- **Per-domain daily limits** — `domain_limits` with `daily_bandwidth` and `daily_connections` (SNI/Host)
- **Limit persistence** — `domain_limits_state_file` (default `/var/lib/snirelay/domain_limits.json`; mount a Docker volume)
- **Mid-transfer bandwidth enforcement** — quota applied per chunk during splice
- **Log file output** — `log_file` / `--log-file` / `LOG_FILE` (stdout + append to file)
- **GitHub Actions** — [`.github/workflows/release-docker.yml`](.github/workflows/release-docker.yml) publishes `ghcr.io` and optional Docker Hub on `v*` tags
- Example production config — [`config/config.limoo.yaml`](config/config.limoo.yaml)

### Changed

- **Routing is `hosts` only** — sniproxy-style `table hosts` for allowlist + DNS/IP override
- **Allowlist:** only hostnames matching a `hosts` pattern are relayed
- **Open proxy:** add `{ pattern: ".*", address: "*" }` under `hosts` to relay all domains
- **Listeners** — `listens` only need `addr` + `proto` (no per-listener `routes`)
- **Branding** — project/binary **snirelay**; removed `pingora-sniproxy` symlink
- **Grafana** — dashboard title **SNIrelay**, uid `snirelay-overview`
- Config alias `limits:` for `domain_limits:`

### Removed

- Per-listener **`routes`** — deprecated; if present in YAML they are **ignored** (startup warning). Use **`hosts`** instead.

### Fixed

- Large downloads could bypass daily bandwidth caps on a single connection
- Domain limits reset on Docker restart (without a state volume)
- `20Mib` and similar byte-size suffixes parse case-insensitively
- Subdomain SNI matches parent `domain_limits` keys (longest match wins)
- `hosts: [{ pattern: ".*", address: "*" }]` no longer bypasses allowlist when specific patterns are used (before routes removal)

### Upgrade notes

1. Remove all `routes:` blocks from `listens`.
2. Move domain allowlist and IP overrides to global **`hosts:`**.
3. Mount `/var/lib/snirelay` if you use **`domain_limits`**.
4. Rebuild/pull image **`0.2.2`** or **`latest`**.

## [0.1.1]

- Accurate byte metrics on partial transfers (`copy_counting`)
- Non-blocking Prometheus `/metrics` snapshots

## [0.1.0]

- Initial public release as **SNIrelay**
