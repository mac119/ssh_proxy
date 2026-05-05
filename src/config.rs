use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// 代理主配置
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub server: ServerConfig,
    pub session: SessionConfig,
    pub audit: AuditConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub host_key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    pub idle_timeout_secs: u64,
    pub max_sessions: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    pub log_dir: String,
    pub record_session: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub max_auth_attempts: u32,
    pub lockout_duration_secs: u64,
}

/// 用户配置
#[derive(Debug, Clone, Deserialize)]
pub struct UsersConfig {
    pub users: Vec<UserEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserEntry {
    pub name: String,
    pub password_hash: String,
    pub public_keys: Vec<String>,
    pub allowed_hosts: Vec<String>,
    /// Command filter mode: "blacklist", "whitelist", or "none" (default)
    #[serde(default = "default_filter_mode")]
    pub command_filter_mode: String,
    /// Commands blocked in blacklist mode (substring match)
    #[serde(default)]
    pub blocked_commands: Vec<String>,
    /// Commands allowed in whitelist mode (prefix match on command name)
    #[serde(default)]
    pub allowed_commands: Vec<String>,
}

fn default_filter_mode() -> String {
    "none".to_string()
}

/// 主机配置
#[derive(Debug, Clone, Deserialize)]
pub struct HostsConfig {
    pub hosts: Vec<HostEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostEntry {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    #[serde(default)]
    pub private_key_path: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// 完整的应用配置
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub session: SessionConfig,
    pub audit: AuditConfig,
    pub security: SecurityConfig,
    pub users: Vec<UserEntry>,
    pub hosts: Vec<HostEntry>,
}

/// 从配置目录加载所有配置
pub fn load_config(config_dir: &str) -> Result<AppConfig> {
    let config_path = Path::new(config_dir);

    // 加载主配置
    let proxy_toml = std::fs::read_to_string(config_path.join("proxy.toml"))
        .context("Failed to read proxy.toml")?;
    let proxy_config: ProxyConfig =
        toml::from_str(&proxy_toml).context("Failed to parse proxy.toml")?;

    // 加载用户配置
    let users_toml = std::fs::read_to_string(config_path.join("users.toml"))
        .context("Failed to read users.toml")?;
    let users_config: UsersConfig =
        toml::from_str(&users_toml).context("Failed to parse users.toml")?;

    // 加载主机配置
    let hosts_toml = std::fs::read_to_string(config_path.join("hosts.toml"))
        .context("Failed to read hosts.toml")?;
    let hosts_config: HostsConfig =
        toml::from_str(&hosts_toml).context("Failed to parse hosts.toml")?;

    Ok(AppConfig {
        server: proxy_config.server,
        session: proxy_config.session,
        audit: proxy_config.audit,
        security: proxy_config.security,
        users: users_config.users,
        hosts: hosts_config.hosts,
    })
}
