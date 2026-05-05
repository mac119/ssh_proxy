# SSH Proxy - 安全审计网关

## 1. 项目概述

SSH Proxy 是一个基于 Rust 实现的 SSH 安全代理网关，用于企业内部服务器的安全访问控制。所有用户通过该代理连接目标服务器，实现统一的身份认证、权限控制和操作审计。

### 核心目标

- **安全代理**: 用户通过 Proxy 连接目标机器，不直接暴露目标机器 SSH 端口
- **身份认证**: 统一认证入口，支持密码和公钥认证
- **权限控制**: 基于用户/角色的目标主机访问控制（ACL）
- **操作审计**: 记录所有 SSH 会话的完整操作日志
- **会话回放**: 支持历史会话的终端回放

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SSH Proxy Gateway                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐              │
│  │  SSH     │    │   Auth &     │    │   Session     │              │
│  │  Server  │───▶│   ACL        │───▶│   Manager     │              │
│  │  (入口)  │    │  (认证/权限)  │    │  (会话管理)    │              │
│  └──────────┘    └──────────────┘    └───────┬───────┘              │
│       ▲                                       │                      │
│       │                                       ▼                      │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐              │
│  │  User    │    │   Audit      │    │   SSH Client  │              │
│  │  Client  │    │   Logger     │◀───│   (出口)      │              │
│  │  (用户)  │    │  (审计日志)   │    │   连接目标机器 │              │
│  └──────────┘    └──────────────┘    └───────────────┘              │
│                         │                                            │
│                         ▼                                            │
│                  ┌──────────────┐                                    │
│                  │   Storage    │                                    │
│                  │  (日志存储)   │                                    │
│                  └──────────────┘                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. 数据流

```
用户 SSH 客户端
       │
       │ 1. SSH 连接请求 (ssh user@proxy -p 2222)
       ▼
┌─────────────────┐
│  SSH Server     │  2. 接受连接，进行用户认证
│  (Proxy 入口)   │
└────────┬────────┘
         │
         │ 3. 认证成功后，展示可访问的目标主机列表
         ▼
┌─────────────────┐
│  Auth & ACL     │  4. 用户选择目标主机，检查权限
│  Module         │
└────────┬────────┘
         │
         │ 5. 权限通过，建立到目标主机的 SSH 连接
         ▼
┌─────────────────┐
│  SSH Client     │  6. 代理转发数据（双向）
│  (Proxy 出口)   │
└────────┬────────┘
         │
         │ 7. 所有数据同时写入审计日志
         ▼
┌─────────────────┐
│  Target Host    │  8. 目标服务器
└─────────────────┘
```

## 4. 模块设计

### 4.1 SSH Server 模块 (`server`)

负责监听端口，接受用户 SSH 连接。

- 监听配置端口（默认 2222）
- 处理 SSH 握手和密钥交换
- 支持 password 和 publickey 认证方式
- 管理 channel 和 PTY 请求

### 4.2 认证与权限模块 (`auth`)

负责用户身份验证和访问控制。

- **用户认证**: 验证用户身份（密码/公钥）
- **ACL 规则**: 定义用户可以访问哪些目标主机
- **配置格式**: TOML 配置文件

```toml
# config/users.toml
[[users]]
name = "admin"
password_hash = "$argon2id$..."
public_keys = ["ssh-rsa AAAA..."]
allowed_hosts = ["*"]  # 可访问所有主机

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

### 4.3 会话管理模块 (`session`)

管理活跃的 SSH 会话。

- 创建/销毁会话
- 维护会话元数据（用户、目标主机、开始时间等）
- 数据双向转发（用户 ↔ 目标主机）
- 会话超时管理

### 4.4 审计日志模块 (`audit`)

记录所有操作用于安全审计。

- **连接日志**: 谁在什么时间连接了哪台机器
- **操作日志**: 记录完整的终端输入/输出流（含时间戳）
- **会话录制**: 以可回放格式（asciicast v2）存储终端会话
- **日志格式**: JSON Lines 格式便于分析

```json
{"timestamp":"2024-01-15T10:30:00Z","event":"session_start","user":"admin","target":"web-server-01","session_id":"abc123"}
{"timestamp":"2024-01-15T10:30:05Z","event":"input","session_id":"abc123","data":"ls -la\r\n"}
{"timestamp":"2024-01-15T10:30:05Z","event":"output","session_id":"abc123","data":"total 48\ndrwxr-xr-x ..."}
{"timestamp":"2024-01-15T10:45:00Z","event":"session_end","session_id":"abc123","duration_secs":900}
```

### 4.5 SSH Client 模块 (`client`)

负责连接目标主机。

- 建立到目标主机的 SSH 连接
- 支持密码和密钥认证
- 请求 PTY 和 shell
- 数据转发

## 5. 技术选型

| 组件 | 选择 | 理由 |
|------|------|------|
| SSH 协议 | `russh` | Rust 原生异步 SSH 实现，支持 server 和 client |
| 异步运行时 | `tokio` | 成熟的异步运行时，russh 基于此 |
| 配置解析 | `toml` + `serde` | Rust 生态标准配置格式 |
| 密码哈希 | `argon2` | 现代安全的密码哈希算法 |
| 日志 | `tracing` | 结构化日志，支持多种输出 |
| 序列化 | `serde_json` | 审计日志 JSON 序列化 |
| 时间处理 | `chrono` | 时间戳处理 |
| UUID | `uuid` | 会话 ID 生成 |

## 6. 项目结构

```
ssh_proxy/
├── Cargo.toml
├── config/
│   ├── proxy.toml          # 代理主配置
│   ├── users.toml          # 用户配置
│   └── hosts.toml          # 目标主机配置
├── src/
│   ├── main.rs             # 入口
│   ├── config.rs           # 配置加载
│   ├── server/
│   │   ├── mod.rs          # SSH Server 入口
│   │   └── handler.rs      # 连接处理
│   ├── client/
│   │   └── mod.rs          # SSH Client（连接目标主机）
│   ├── auth/
│   │   ├── mod.rs          # 认证逻辑
│   │   └── acl.rs          # 权限控制
│   ├── session/
│   │   └── mod.rs          # 会话管理
│   └── audit/
│       ├── mod.rs          # 审计日志
│       └── recorder.rs     # 会话录制
├── logs/                   # 审计日志输出目录
└── README.md
```

## 7. 用户交互流程

1. 用户执行: `ssh user@proxy-host -p 2222`
2. Proxy 验证用户身份
3. 认证成功后，Proxy 向用户展示可访问的主机列表:
   ```
   Welcome, admin! Available hosts:
   [1] web-server-01 (192.168.1.10)
   [2] web-server-02 (192.168.1.11)
   [3] db-server-01  (192.168.1.20)
   Select host:
   ```
4. 用户选择目标主机
5. Proxy 建立到目标主机的连接
6. 数据双向透明转发，同时记录审计日志
7. 用户断开连接时，关闭会话并记录结束事件

## 8. 安全考虑

- Proxy 服务器的 host key 应妥善保管
- 用户密码使用 Argon2id 哈希存储
- 目标主机私钥文件权限限制为 600
- 审计日志不可篡改（append-only）
- 支持会话超时自动断开
- 失败登录次数限制

## 9. 后续扩展

- Web 管理界面（查看在线会话、回放历史会话）
- 数据库后端（替代 TOML 文件配置）
- 多因素认证（MFA/TOTP）
- 命令黑名单/白名单过滤
- 文件传输（SCP/SFTP）审计
- 集群部署与负载均衡
