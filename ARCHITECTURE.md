# SSH Guard Proxy - Architecture Document

## 1. Overview

SSH Guard Proxy is a security-focused SSH proxy gateway built in Rust. All users connect to target servers through this proxy, enabling unified authentication, access control, and full operation auditing.

### Core Objectives

- **Secure Proxy**: Users connect through the proxy — target server SSH ports are never directly exposed
- **Authentication**: Unified authentication entry point supporting password and public key methods
- **Access Control**: Role/user-based target host access control (ACL)
- **Audit Logging**: Complete operation logging for all SSH sessions
- **Session Replay**: Full terminal session recording with playback capability

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SSH Guard Proxy Gateway                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐              │
│  │   SSH    │    │   Auth &     │    │   Session     │              │
│  │  Server  │───▶│   ACL        │───▶│   Manager     │              │
│  │ (Inbound)│    │(Auth/Authz)  │    │ (Management)  │              │
│  └──────────┘    └──────────────┘    └───────┬───────┘              │
│       ▲                                       │                      │
│       │                                       ▼                      │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐              │
│  │   User   │    │   Audit      │    │  SSH Client   │              │
│  │  Client  │    │   Logger     │◀───│  (Outbound)   │              │
│  │          │    │              │    │ Connect Target │              │
│  └──────────┘    └──────────────┘    └───────────────┘              │
│                         │                                            │
│                         ▼                                            │
│                  ┌──────────────┐                                    │
│                  │   Storage    │                                    │
│                  │ (Log Files)  │                                    │
│                  └──────────────┘                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Data Flow

```
User SSH Client
       │
       │ 1. SSH connection request (ssh user@proxy -p 2222)
       ▼
┌─────────────────┐
│  SSH Server     │  2. Accept connection, authenticate user
│  (Proxy Inbound)│
└────────┬────────┘
         │
         │ 3. On success, display list of accessible target hosts
         ▼
┌─────────────────┐
│  Auth & ACL     │  4. User selects target host, verify permissions
│  Module         │
└────────┬────────┘
         │
         │ 5. Permission granted, establish SSH connection to target
         ▼
┌─────────────────┐
│  SSH Client     │  6. Bidirectional data relay
│ (Proxy Outbound)│
└────────┬────────┘
         │
         │ 7. All data simultaneously written to audit log
         ▼
┌─────────────────┐
│  Target Host    │  8. Destination server
└─────────────────┘
```

## 4. Module Design

### 4.1 SSH Server Module (`server`)

Listens for and accepts incoming user SSH connections.

- Listens on configured port (default 2222)
- Handles SSH handshake and key exchange
- Supports `password` and `publickey` authentication methods
- Manages channels and PTY requests

### 4.2 Authentication & Authorization Module (`auth`)

Handles user identity verification and access control.

- **User Authentication**: Verify user identity (password/public key)
- **ACL Rules**: Define which target hosts each user can access
- **Configuration Format**: TOML files

```toml
# config/users.toml
[[users]]
name = "admin"
password_hash = "$argon2id$..."
public_keys = ["ssh-rsa AAAA..."]
allowed_hosts = ["*"]  # Access to all hosts

[[users]]
name = "developer"
password_hash = "$argon2id$..."
public_keys = ["ssh-ed25519 AAAA..."]
allowed_hosts = ["web-server-01", "web-server-02"]

# config/hosts.toml
[[hosts]]
name = "web-server-01"
address = "192.168.1.10"
port = 22
username = "deploy"
auth_method = "key"  # key | password
private_key_path = "/etc/ssh_proxy/keys/web-server-01"
```

### 4.3 Session Management Module (`session`)

Manages active SSH sessions.

- Create/destroy sessions
- Maintain session metadata (user, target host, start time, etc.)
- Bidirectional data forwarding (User ↔ Target Host)
- Session idle timeout management

### 4.4 Audit Logging Module (`audit`)

Records all operations for security auditing.

- **Connection Logs**: Who connected to which machine and when
- **Operation Logs**: Complete terminal input/output stream with timestamps
- **Session Recording**: Stored in replayable format (asciicast v2)
- **Log Format**: JSON Lines for easy analysis

```json
{"timestamp":"2026-01-15T10:30:00Z","event":"session_start","user":"admin","target":"web-server-01","session_id":"abc123"}
{"timestamp":"2026-01-15T10:30:05Z","event":"data","session_id":"abc123","direction":"input","data_base64":"bHMgLWxhCg==","data_len":7}
{"timestamp":"2026-01-15T10:30:05Z","event":"data","session_id":"abc123","direction":"output","data_base64":"dG90YWwgNDgK...","data_len":256}
{"timestamp":"2026-01-15T10:45:00Z","event":"session_end","session_id":"abc123"}
```

### 4.5 SSH Client Module (`client`)

Connects to target hosts on behalf of the user.

- Establishes SSH connections to target hosts
- Supports both password and key-based authentication
- Requests PTY and shell
- Bidirectional data forwarding via `tokio::sync::mpsc` channels

## 5. Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| SSH Protocol | `russh` | Native async Rust SSH implementation (server + client) |
| Async Runtime | `tokio` | Mature async runtime; russh is built on it |
| Configuration | `toml` + `serde` | Standard config format in the Rust ecosystem |
| Password Hashing | `argon2` | Modern, secure password hashing (PHC winner) |
| Logging | `tracing` | Structured logging with multiple output targets |
| Serialization | `serde_json` | Audit log JSON serialization |
| Time Handling | `chrono` | Timestamp processing |
| UUID | `uuid` | Session ID generation |

## 6. Project Structure

```
ssh_proxy/
├── Cargo.toml
├── config/
│   ├── proxy.toml          # Main proxy configuration
│   ├── users.toml          # User configuration
│   └── hosts.toml          # Target host configuration
├── src/
│   ├── main.rs             # Entry point
│   ├── config.rs           # Configuration loading
│   ├── server/
│   │   ├── mod.rs          # SSH Server (TCP listener + session spawning)
│   │   └── handler.rs      # Connection handler (auth, relay, menu)
│   ├── client/
│   │   └── mod.rs          # SSH Client (connects to target hosts)
│   ├── auth/
│   │   ├── mod.rs          # Authentication logic
│   │   └── acl.rs          # Access control
│   ├── session/
│   │   └── mod.rs          # Session management
│   └── audit/
│       ├── mod.rs          # Audit logger
│       └── recorder.rs     # Session recording (asciicast v2)
├── src/bin/
│   └── hash_password.rs    # CLI tool for generating password hashes
├── logs/                   # Audit log output directory
└── README.md
```

## 7. User Interaction Flow

1. User runs: `ssh user@proxy-host -p 2222`
2. Proxy verifies user identity
3. On successful authentication, Proxy displays accessible host list:
   ```
   Welcome, admin! Available hosts:
   ─────────────────────────────────────
     [1] web-server-01 (192.168.1.10:22)
     [2] web-server-02 (192.168.1.11:22)
     [3] db-server-01  (192.168.1.20:22)
   ─────────────────────────────────────
   Select host number:
   ```
4. User selects target host
5. Proxy establishes connection to target host
6. Data is transparently relayed bidirectionally while audit log records everything
7. When user disconnects, session is closed and end event is logged

## 8. Security Considerations

- Proxy server host key must be securely stored
- User passwords stored using Argon2id hashing
- Target host private key files restricted to permission 600
- Audit logs are append-only (tamper-resistant)
- Session idle timeout with automatic disconnect
- Failed login attempt rate limiting with lockout

## 9. Future Roadmap

- Web management UI (view live sessions, replay history)
- Database backend (replace TOML file configuration)
- Multi-factor authentication (MFA/TOTP)
- Command blacklist/whitelist filtering
- File transfer (SCP/SFTP) auditing
- Cluster deployment with load balancing
- Real-time alerting on suspicious activity
- Session sharing (multiple admins observing one session)
