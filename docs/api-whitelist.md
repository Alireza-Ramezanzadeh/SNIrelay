# Panel backend API — whitelist & per-IP upstream

Admin API for SNIrelay. Use this from an external panel backend.

**Base URL:** `http://<SNIRELAY_HOST>:9080`

---

## Authentication

All endpoints below require a session cookie.

### Login

```http
POST /api/auth/login
Content-Type: application/json
```

```json
{ "password": "<ADMIN_PASSWORD>" }
```

**200** → `{ "ok": true }`  
**Set-Cookie:** `snirelay_session=<token>; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800` (7 days)

Send on every request:

```http
Cookie: snirelay_session=<token>
```

### Logout

```http
POST /api/auth/logout
Cookie: snirelay_session=<token>
```

---

# 1) Client IP whitelist

### Semantics

| State | Behavior |
|-------|----------|
| Empty list | ACL **off** — all clients allowed (`open: true`) |
| Non-empty | Only listed IPs may use proxy listeners (`open: false`) |

- Panel HTTP (`:9080`) is **never** filtered.
- Changes hot-reload + persist to YAML `client_whitelist` / `client_whitelist_ufw`.
- When `ufw_sync` is on, UFW rules are synced via `nsenter -t 1 -m -n` into the host
  (Docker **must** have `privileged: true` and `pid: host`; recreate after changing compose).
- **Username is required** on add. UFW comment becomes `snirelay:<username>`.

Username rules: letters, digits, `._@+-`, max 32 chars (after sanitize).

---

### List

```http
GET /api/whitelist
Cookie: snirelay_session=<token>
```

```json
{
  "ips": ["151.239.115.236"],
  "entries": [
    { "ip": "151.239.115.236", "username": "alice" }
  ],
  "open": false,
  "ufw_sync": true,
  "ufw_available": true,
  "ufw_bin": null,
  "note": "…"
}
```

Prefer `entries` (includes username). `ips` is kept for convenience.

---

### Add / update one IP (recommended)

```http
POST /api/whitelist/add
Cookie: snirelay_session=<token>
Content-Type: application/json
```

```json
{
  "ip": "151.239.115.236",
  "username": "alice"
}
```

**200**

```json
{
  "ok": true,
  "added": true,
  "username": "alice",
  "ufw_comment": "snirelay:alice",
  "persist": "saved",
  "ips": ["151.239.115.236"],
  "entries": [
    { "ip": "151.239.115.236", "username": "alice" }
  ],
  "open": false,
  "ufw": "Rule added"
}
```

| Field | Meaning |
|-------|---------|
| `added` | `true` if new IP; `false` if IP existed (username/UFW comment refreshed) |
| `ufw_comment` | Exact comment written to UFW |
| `ufw` | Host ufw result, or error string |

**400** — invalid IP or missing/invalid username:

```json
{ "error": "username required (letters, digits, . _ @ + -; max 32 chars)" }
```

---

### Delete one IP

```http
DELETE /api/whitelist/{ip}
Cookie: snirelay_session=<token>
```

URL-encode `{ip}` (IPv6). Example: `DELETE /api/whitelist/151.239.115.236`

```json
{
  "ok": true,
  "removed": true,
  "persist": "saved",
  "ips": [],
  "entries": [],
  "open": true,
  "ufw": "Rule deleted"
}
```

Removing the last IP sets `open: true` (ACL off).

---

### Replace full list

```http
PUT /api/whitelist
Cookie: snirelay_session=<token>
Content-Type: application/json
```

Preferred body:

```json
{
  "entries": [
    { "ip": "1.2.3.4", "username": "alice" },
    { "ip": "5.6.7.8", "username": "bob" }
  ],
  "ufw_sync": true
}
```

Legacy (no usernames — UFW comment falls back to `snirelay-whitelist`):

```json
{ "ips": ["1.2.3.4"], "ufw_sync": true }
```

Open ACL:

```json
{ "entries": [] }
```

---

### YAML on disk

```yaml
client_whitelist:
  - ip: "151.239.115.236"
    username: alice
  - "94.183.122.121"          # legacy IP-only still loads
client_whitelist_ufw: true
```

UFW example:

```text
[ 1] Anywhere                   ALLOW IN    151.239.115.236            # snirelay:alice
```

---

### Whitelist curl

```bash
BASE=http://95.156.253.115:9080
curl -sS -c /tmp/sni.txt -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"password":"YOUR_PASSWORD"}'

curl -sS -b /tmp/sni.txt -X POST "$BASE/api/whitelist/add" \
  -H 'Content-Type: application/json' \
  -d '{"ip":"151.239.115.236","username":"alice"}'

curl -sS -b /tmp/sni.txt "$BASE/api/whitelist"

curl -sS -b /tmp/sni.txt -X DELETE "$BASE/api/whitelist/151.239.115.236"
```

---

# 2) Per-IP upstream routing

Named SOCKS/HTTP profiles live in YAML `upstreams`.  
Exact client IP → profile name is `client_upstreams`.  
Unmapped clients use `default_upstream`.

Changes hot-reload for **new** connections and persist to YAML.

---

### List profiles + client map

```http
GET /api/upstreams
Cookie: snirelay_session=<token>
```

```json
{
  "upstreams": {
    "default": { "type": "socks5", "host": "127.0.0.1", "port": 10808 },
    "europe": { "type": "socks5", "host": "10.0.0.2", "port": 1080 }
  },
  "default_upstream": "default",
  "client_upstreams": {
    "151.239.115.236": "europe"
  },
  "upstream_failover": false
}
```

---

### Set / update one client → profile (recommended)

```http
POST /api/upstreams/client
Cookie: snirelay_session=<token>
Content-Type: application/json
```

```json
{
  "ip": "151.239.115.236",
  "profile": "europe"
}
```

**200**

```json
{
  "ok": true,
  "persist": "saved",
  "ip": "151.239.115.236",
  "profile": "europe",
  "client_upstreams": {
    "151.239.115.236": "europe"
  },
  "default_upstream": "default"
}
```

**400** — invalid IP or unknown profile name.

Idempotent: calling again with the same or a different profile overwrites the mapping.

---

### Remove per-IP mapping

```http
DELETE /api/upstreams/client/{ip}
Cookie: snirelay_session=<token>
```

After removal, that client falls back to `default_upstream`.

```json
{
  "ok": true,
  "removed": true,
  "persist": "saved",
  "client_upstreams": {},
  "default_upstream": "default"
}
```

---

### Replace full upstream config (advanced)

```http
PUT /api/upstreams
Cookie: snirelay_session=<token>
Content-Type: application/json
```

```json
{
  "upstreams": {
    "default": { "type": "socks5", "host": "127.0.0.1", "port": 10808 },
    "europe": { "type": "socks5", "host": "10.0.0.2", "port": 1080 }
  },
  "default_upstream": "default",
  "client_upstreams": {
    "151.239.115.236": "europe"
  },
  "upstream_failover": false
}
```

Use this for bulk edits / creating profiles. For day-to-day panel flows prefer  
`POST/DELETE /api/upstreams/client`.

Profile types: `socks5` | `http` | `direct`.

---

### Upstream curl

```bash
# Assign client to profile
curl -sS -b /tmp/sni.txt -X POST "$BASE/api/upstreams/client" \
  -H 'Content-Type: application/json' \
  -d '{"ip":"151.239.115.236","profile":"europe"}'

# Clear mapping (use default)
curl -sS -b /tmp/sni.txt -X DELETE \
  "$BASE/api/upstreams/client/151.239.115.236"

# Inspect
curl -sS -b /tmp/sni.txt "$BASE/api/upstreams"
```

---

# Typical panel backend flow

1. `POST /api/auth/login` → store cookie.
2. User activates →  
   - `POST /api/whitelist/add` `{ ip, username }`  
   - optional `POST /api/upstreams/client` `{ ip, profile }`
3. User expires →  
   - `DELETE /api/whitelist/{ip}`  
   - `DELETE /api/upstreams/client/{ip}`

---

# Errors

| HTTP | When |
|------|------|
| `401` | Missing/invalid session |
| `400` | Invalid IP, username, or unknown upstream profile |
| `200` + `persist` contains `YAML save failed` | Runtime updated; file write failed |

---

# Notes

- Capture the client’s **public** IP (what SNIrelay sees on `:80`/`:443`).
- Whitelist username is for UFW labeling / ops — not used for auth.
- First whitelist IP enables ACL; unlisted clients are rejected at the proxy.
- Per-IP upstream only affects routing; it does not open the firewall — use whitelist for that.
