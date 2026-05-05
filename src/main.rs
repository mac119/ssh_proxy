#![allow(dead_code, unused_variables)]

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod audit;
mod auth;
mod client;
mod config;
mod filter;
mod server;
mod session;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("ssh_proxy=info".parse()?))
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("SSH Proxy Gateway starting...");

    // 加载配置
    let config = config::load_config("config")?;
    info!(
        "Configuration loaded: listening on {}:{}",
        config.server.listen_address, config.server.listen_port
    );
    info!("Loaded {} users, {} hosts", config.users.len(), config.hosts.len());

    // 启动 SSH Server
    server::run(config).await?;

    Ok(())
}
