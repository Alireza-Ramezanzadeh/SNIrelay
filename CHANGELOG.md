# Changelog

All notable changes to **SNIrelay** are documented in this file.

## [0.2.0] — 2026-05-23

### Added

- **Per-domain daily limits** — `daily_bandwidth` and `daily_connections` by TLS SNI / HTTP Host
- **Limit persistence** — Counters saved to `/var/lib/snirelay/domain_limits.json` (survives Docker restarts; mount a volume)
- **Mid-transfer bandwidth enforcement** — Quota applied per chunk during splice, not only after disconnect
- **Log file output** — `log_file` / `--log-file` / `LOG_FILE` append logs to disk
- **GitHub Actions** — `.github/workflows/release-docker.yml` publishes `ghcr.io` (+ optional Docker Hub) on `v*` tags

### Changed

- Project branding: removed `pingora-sniproxy` binary symlink and references; use **`snirelay`** only
- Docker image user/group renamed to `snirelay`
- Grafana dashboard title/uid updated to **SNIrelay** (`snirelay-overview`)

### Fixed

- Large downloads could bypass daily bandwidth caps on a single connection
- `20Mib` and similar byte-size suffixes parse case-insensitively
- Subdomain SNI matches parent domain limit keys (longest match wins)

## [0.1.1]

- Accurate byte metrics on partial transfers (`copy_counting`)
- Non-blocking Prometheus `/metrics` snapshots

## [0.1.0]

- Initial public release as **SNIrelay**
