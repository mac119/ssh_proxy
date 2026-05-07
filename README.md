<div align="center">

```
    ┌─────────────────────────────────┐
    │         ╔═══╗                   │
    │         ║ ⬡ ║  SSH GUARD        │
    │         ╚═══╝                   │
    │    ┌───┐       ┌───┐  ┌───┐    │
    │    │ U ├──→ P ─┤ T │  │ T │    │
    │    └───┘  ↕    └───┘  └───┘    │
    │         AUDIT                   │
    └─────────────────────────────────┘
```

# 🛡️ SSH Guard Proxy

**A high-performance SSH proxy gateway built in Rust for security auditing, access control, and session recording.**

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![tokio](https://img.shields.io/badge/async-tokio-blue)](https://tokio.rs/)

*Every keystroke recorded. Every connection authorized. Every session auditable.*

</div>

---

## 🎯 Why SSH Guard Proxy?

In modern infrastructure, direct SSH access to production servers is a **security risk**. SSH Guard Proxy solves this by acting as a **single point of entry** — a bastion host that enforces authentication, authorization, and full audit logging for every SSH session.

### The Problem

- Developers SSH directly into production servers with no oversight
- No centralized record of who did what and when
- Shared credentials make accountability impossible
- Revoking access requires touching every server

### The Solution

```
Developer → SSH Guard Proxy → Target Server
                ↓
          Audit Log (every keystroke)
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Unified Authentication** | Password (Argon2id) and public key auth at the gateway |
| 🎛️ **Access Control (ACL)** | Per-user host access policies — who can access what |
| 📝 **Full Audit Logging** | Every input/output recorded in JSON Lines format |
| 🎬 **Session Recording** | Asciicast v2 format — replay any session with `asciinema` |
| ⚡ **High Performance** | Built on Rust + Tokio async runtime — minimal overhead |
| 🏗️ **Zero Target Changes** | No agent or modification needed on target servers |
| 🔑 **Host Key Auto-generation** | Ed25519 host keys generated on first run |
| 🚦 **Connection Limiting** | Max session control and auth failure lockout |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      SSH Guard Proxy                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   User ──SSH──→ [SSH Server] ──→ [Auth & ACL] ──→ [Session Mgr]  │
│                                                        │          │
│                                                        ▼          │
│                  [Audit Logger] ◀────────────── [SSH Client] ──→ Target
│                       │                                           │
│                       ▼                                           │
│                 logs/audit.jsonl                                   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. User connects: `ssh admin@proxy -p 2222`
2. Proxy authenticates the user (password or public key)
3. User selects a target host from the authorized list
4. Proxy establishes SSH connection to target
5. All data is bidirectionally forwarded **and** logged
6. Session ends → audit record finalized

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.70+ (install via [rustup](https://rustup.rs/))
- Target servers accessible via SSH from the proxy host

### Build

```bash
git clone https://github.com/mac119/ssh_proxy.git
cd ssh_proxy
cargo build --release
```

### Configure

#### 1. Proxy Settings (`config/proxy.toml`)

```toml
[server]
listen_address = "0.0.0.0"
listen_port = 2222
host_key_path = "config/host_key"

[session]
idle_timeout_secs = 1800
max_sessions = 100

[audit]
log_dir = "logs"
record_session = true

[security]
max_auth_attempts = 3
lockout_duration_secs = 300
```

#### 2. Add Users (`config/users.toml`)

Generate a password hash first:

```bash
cargo run --bin hash_password -- 'YourSecurePassword'
# Output: $argon2id$v=19$m=19456,t=2,p=1$...
```

Then add to config:

```toml
[[users]]
name = "admin"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
public_keys = []
allowed_hosts = ["*"]  # Access to all hosts

[[users]]
name = "developer"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
public_keys = ["ssh-ed25519 AAAAC3Nza..."]
allowed_hosts = ["web-01", "web-02"]  # Restricted access
```

#### 3. Add Target Hosts (`config/hosts.toml`)

```toml
[[hosts]]
name = "web-01"
address = "192.168.1.10"
port = 22
username = "deploy"
auth_method = "key"
private_key_path = "config/keys/web-01"

[[hosts]]
name = "db-01"
address = "10.0.0.50"
port = 22
username = "dbadmin"
auth_method = "password"
password = "encrypted:your_password_here"
```

### Run

```bash
# Development
cargo run

# Production
./target/release/ssh_proxy
```

### Connect

```bash
ssh admin@your-proxy-host -p 2222
```

You'll see:

```
Welcome, admin! Available hosts:
─────────────────────────────────────
  [1] web-01 (192.168.1.10:22)
  [2] web-02 (192.168.1.11:22)
  [3] db-01 (10.0.0.50:22)
─────────────────────────────────────
Select host number: 
```

Select a host and you're in — fully transparent, fully audited.

### File Transfer (SCP/SFTP)

SSH Guard Proxy supports **SCP and SFTP file transfers** with full audit logging. All file transfers are recorded — including filenames, sizes, direction, and timestamps.

#### Upload a File

```bash
# Upload to the default target host (first allowed host)
scp -P 2222 myfile.txt admin@proxy-host:/tmp/

# Upload to a specific target host (use user%host format)
scp -P 2222 myfile.txt admin%db-server-01@proxy-host:/tmp/

# Recursive directory upload
scp -r -P 2222 ./my-folder admin%web-server-01@proxy-host:/opt/
```

#### Download a File

```bash
# Download from the default target host
scp -P 2222 admin@proxy-host:/etc/hosts ./

# Download from a specific target host
scp -P 2222 admin%db-server-01@proxy-host:/var/log/app.log ./
```

#### Legacy SCP Mode

Modern OpenSSH (9.0+) uses SFTP by default for `scp` commands. Both modes are fully supported:

```bash
# Default (SFTP mode) — works out of the box
scp -P 2222 file.txt admin@proxy-host:/tmp/

# Force legacy SCP protocol (if needed)
scp -O -P 2222 file.txt admin@proxy-host:/tmp/
```

#### Target Host Selection

| Method | Example | Description |
|--------|---------|-------------|
| Default | `admin@proxy` | Uses the first allowed host from ACL |
| Explicit | `admin%db-server-01@proxy` | Specifies exact target host by name |

#### SCP Audit Log Events

All file transfers generate audit entries:

```json
{"event":"scp_session_start","session_id":"...","user":"admin","direction":"upload","target_host":"db-server-01","remote_path":"/tmp/"}
{"event":"scp_file_transfer","session_id":"...","user":"admin","direction":"upload","filename":"myfile.txt","size":10240,"mode":"0644"}
```

---

## 📊 Audit Logs

All audit data is stored in `logs/audit.jsonl` in append-only JSON Lines format.

### Log Events

| Event | Description |
|-------|-------------|
| `auth_success` | Successful authentication |
| `auth_failure` | Failed authentication attempt |
| `session_start` | User connected to a target host |
| `session_end` | Session terminated |
| `data` (input) | User keystrokes / commands |
| `data` (output) | Server responses |
| `command_blocked` | Command rejected by filter |
| `scp_session_start` | SCP/SFTP transfer session initiated |
| `scp_file_transfer` | File transferred (name, size, direction) |

### Example Log Entries

```json
{"event":"auth_success","timestamp":"2026-05-05T07:10:00Z","user":"admin","peer_addr":"10.0.1.5:54321","method":"password"}
{"event":"session_start","timestamp":"2026-05-05T07:10:05Z","session_id":"a1b2c3d4","user":"admin","peer_addr":"10.0.1.5:54321","target_host":"web-01","target_addr":"192.168.1.10"}
{"event":"data","timestamp":"2026-05-05T07:10:10Z","session_id":"a1b2c3d4","direction":"input","data_base64":"bHMgLWxhCg==","data_len":7}
{"event":"data","timestamp":"2026-05-05T07:10:10Z","session_id":"a1b2c3d4","direction":"output","data_base64":"dG90YWwgNDgK...","data_len":256}
{"event":"session_end","timestamp":"2026-05-05T07:45:00Z","session_id":"a1b2c3d4"}
```

### Decoding Commands from Logs

```bash
# View all input commands from a session
grep '"direction":"input"' logs/audit.jsonl | \
  jq -r '.data_base64' | \
  while read line; do echo "$line" | base64 -d; done

# Find who connected today
grep '"event":"session_start"' logs/audit.jsonl | \
  grep "$(date +%Y-%m-%d)" | \
  jq '{user, target_host, timestamp}'

# Count failed logins
grep '"event":"auth_failure"' logs/audit.jsonl | wc -l
```

### Session Replay

Sessions are recorded in [asciicast v2](https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md) format:

```bash
# Replay a recorded session
asciinema play logs/sessions/<session_id>.cast
```

---

## 🏢 Production Deployment

### Systemd Service

Create `/etc/systemd/system/ssh-guard-proxy.service`:

```ini
[Unit]
Description=SSH Guard Proxy
After=network.target

[Service]
Type=simple
User=sshproxy
Group=sshproxy
WorkingDirectory=/opt/ssh_proxy
ExecStart=/opt/ssh_proxy/ssh_proxy
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/ssh_proxy/logs

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ssh-guard-proxy
sudo systemctl start ssh-guard-proxy
```

### File Permissions

```bash
chmod 600 config/host_key
chmod 600 config/keys/*
chmod 644 config/*.toml
chmod 700 logs/
```

### Log Rotation

Add to `/etc/logrotate.d/ssh-guard-proxy`:

```
/opt/ssh_proxy/logs/audit.jsonl {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### Firewall

```bash
# Only expose the proxy port
ufw allow 2222/tcp
# Block direct SSH to target hosts from outside
ufw deny from any to 192.168.1.0/24 port 22
```

---

## 📁 Project Structure

```
ssh_proxy/
├── Cargo.toml                 # Dependencies & build config
├── config/
│   ├── proxy.toml             # Main proxy configuration
│   ├── users.toml             # User accounts & ACL
│   ├── hosts.toml             # Target host definitions
│   └── host_key              # Auto-generated Ed25519 host key
├── src/
│   ├── main.rs               # Entry point
│   ├── config.rs             # Configuration loading
│   ├── server/
│   │   ├── mod.rs            # TCP listener & session spawning
│   │   └── handler.rs        # SSH protocol handler (auth, data relay)
│   ├── client/
│   │   └── mod.rs            # SSH client (connects to targets)
│   ├── auth/
│   │   ├── mod.rs            # Authentication (Argon2id, pubkey)
│   │   └── acl.rs            # Access control logic
│   ├── session/
│   │   └── mod.rs            # Session lifecycle management
│   └── audit/
│       ├── mod.rs            # Audit event logger
│       └── recorder.rs       # Asciicast session recorder
├── src/bin/
│   └── hash_password.rs      # CLI tool to generate password hashes
└── logs/                      # Audit output directory
```

---

## 🔧 Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | **Rust** | Memory safety, zero-cost abstractions, fearless concurrency |
| SSH Protocol | **russh** | Native async SSH implementation (server + client) |
| Async Runtime | **Tokio** | Industry-standard, battle-tested async runtime |
| Password Hashing | **Argon2id** | Winner of Password Hashing Competition |
| Logging | **tracing** | Structured, async-aware instrumentation |
| Config | **TOML + serde** | Human-readable, type-safe configuration |

---

## 🗺️ Roadmap

- [ ] Web management UI (live sessions, replay, user management)
- [ ] Database backend (PostgreSQL/SQLite for config & logs)
- [ ] Multi-factor authentication (TOTP/WebAuthn)
- [x] Command blacklist/whitelist filtering
- [x] SCP/SFTP file transfer auditing
- [ ] Cluster mode with load balancing
- [ ] Real-time alerting (Slack/webhook on suspicious activity)
- [ ] Session sharing (multiple admins watching one session)

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with 🦀 Rust for maximum performance and safety.**

*SSH Guard Proxy — Because security shouldn't be an afterthought.*

</div>
