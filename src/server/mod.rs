pub mod handler;

use anyhow::Result;
use russh::server::Config;
use russh_keys::key::KeyPair;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::audit::AuditLogger;
use crate::auth::Authenticator;
use crate::config::AppConfig;
use crate::session::SessionManager;

use self::handler::ProxyHandler;

/// 启动 SSH Proxy 服务器
pub async fn run(config: AppConfig) -> Result<()> {
    let config = Arc::new(config);

    // 加载或生成 host key
    let key_pair = load_or_generate_host_key(&config.server.host_key_path).await?;

    // 构建 russh server 配置
    let russh_config = Config {
        keys: vec![key_pair],
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        ..Default::default()
    };

    let russh_config = Arc::new(russh_config);

    // 初始化各模块
    let authenticator = Arc::new(Authenticator::new(config.users.clone(), &config.security));
    let session_manager = Arc::new(Mutex::new(SessionManager::new(config.session.max_sessions)));
    let audit_logger = Arc::new(AuditLogger::new(&config.audit.log_dir)?);

    let listen_addr = format!("{}:{}", config.server.listen_address, config.server.listen_port);
    info!("SSH Proxy listening on {}", listen_addr);

    let listener = TcpListener::bind(&listen_addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("New connection from: {}", peer_addr);

        let handler = ProxyHandler::new(
            peer_addr.to_string(),
            authenticator.clone(),
            session_manager.clone(),
            audit_logger.clone(),
            config.clone(),
        );

        let cfg = russh_config.clone();

        tokio::spawn(async move {
            match russh::server::run_stream(cfg, stream, handler).await {
                Ok(session) => {
                    // 等待会话结束
                    if let Err(e) = session.await {
                        error!("Session error for {}: {:?}", peer_addr, e);
                    }
                }
                Err(e) => {
                    error!("Failed to start session for {}: {:?}", peer_addr, e);
                }
            }
        });
    }
}

/// 加载或生成 SSH host key
async fn load_or_generate_host_key(path: &str) -> Result<KeyPair> {
    let key_path = std::path::Path::new(path);

    if key_path.exists() {
        info!("Loading host key from: {}", path);
        let key = russh_keys::load_secret_key(path, None)?;
        Ok(key)
    } else {
        info!("Generating new Ed25519 host key at: {}", path);
        let key = KeyPair::generate_ed25519();

        // 确保父目录存在
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // 保存私钥到文件
        let mut file = std::fs::File::create(path)?;
        russh_keys::encode_pkcs8_pem(&key, &mut file)?;

        // 设置文件权限 (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(key)
    }
}
