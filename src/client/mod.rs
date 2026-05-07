use anyhow::{Context, Result};
use russh::client;
use russh_keys::key::PublicKey;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::HostEntry;

/// 从目标主机接收的数据
pub type DataReceiver = mpsc::UnboundedReceiver<Vec<u8>>;
type DataSender = mpsc::UnboundedSender<Vec<u8>>;

/// SSH Client 用于连接目标主机
pub struct SshClient {
    session: client::Handle<ClientHandler>,
    channel_id: russh::ChannelId,
}

/// russh client handler —— 将目标主机的输出通过 channel 转发
struct ClientHandler {
    data_tx: DataSender,
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: 实现 known_hosts 检查
        Ok(true)
    }

    /// 接收目标主机发来的数据，通过 mpsc channel 转发
    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        data: &[u8],
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.data_tx.send(data.to_vec());
        Ok(())
    }
}

impl SshClient {
    /// 连接到目标主机，返回 (SshClient, DataReceiver)
    /// DataReceiver 用于接收目标主机返回的数据
    pub async fn connect(host: &HostEntry) -> Result<(Self, DataReceiver)> {
        let config = Arc::new(client::Config::default());

        // 创建数据通道：目标主机输出 -> proxy -> 用户
        let (data_tx, data_rx) = mpsc::unbounded_channel();

        let handler = ClientHandler { data_tx };

        let addr = format!("{}:{}", host.address, host.port);
        info!("Connecting to target host: {}", addr);

        let mut session = client::connect(config, &addr, handler)
            .await
            .context(format!("Failed to connect to {}", addr))?;

        // 认证
        match host.auth_method.as_str() {
            "key" => {
                let key_path = host
                    .private_key_path
                    .as_deref()
                    .context("Private key path not configured")?;
                let key = russh_keys::load_secret_key(key_path, None)
                    .context("Failed to load private key")?;
                let auth_result = session
                    .authenticate_publickey(&host.username, Arc::new(key))
                    .await
                    .context("Public key authentication failed")?;
                if !auth_result {
                    anyhow::bail!("Public key authentication rejected by target host");
                }
            }
            "password" => {
                let password = host
                    .password
                    .as_deref()
                    .context("Password not configured for host")?;
                let pwd = password.strip_prefix("encrypted:").unwrap_or(password);
                let auth_result = session
                    .authenticate_password(&host.username, pwd)
                    .await
                    .context("Password authentication failed")?;
                if !auth_result {
                    anyhow::bail!("Password authentication rejected by target host");
                }
            }
            other => {
                anyhow::bail!("Unsupported auth method: {}", other);
            }
        }

        info!("Authenticated to target host: {}", addr);

        // 打开 channel 并请求 shell
        let channel = session
            .channel_open_session()
            .await
            .context("Failed to open channel")?;

        let channel_id = channel.id();

        // 请求 PTY
        channel
            .request_pty(false, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .context("Failed to request PTY")?;

        // 请求 shell
        channel
            .request_shell(false)
            .await
            .context("Failed to request shell")?;

        Ok((
            Self {
                session,
                channel_id,
            },
            data_rx,
        ))
    }

    /// 向目标主机发送数据
    pub async fn send_data(&self, data: &[u8]) -> Result<()> {
        self.session
            .data(self.channel_id, russh::CryptoVec::from(data.to_vec()))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send data: {:?}", e))?;
        Ok(())
    }

    /// 发送 EOF/关闭信号到目标主机（通过 disconnect）
    pub async fn send_eof(&self) -> Result<()> {
        self.session
            .disconnect(russh::Disconnect::ByApplication, "Transfer complete", "en")
            .await?;
        Ok(())
    }

    /// 连接到目标主机并执行命令（用于 SCP/exec 模式，无 PTY）
    pub async fn connect_exec(host: &HostEntry, command: &str) -> Result<(Self, DataReceiver)> {
        let config = Arc::new(client::Config::default());
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let handler = ClientHandler { data_tx };

        let addr = format!("{}:{}", host.address, host.port);
        info!("Connecting to target host (exec mode): {}", addr);

        let mut session = client::connect(config, &addr, handler)
            .await
            .context(format!("Failed to connect to {}", addr))?;

        // 认证（与 connect 相同）
        match host.auth_method.as_str() {
            "key" => {
                let key_path = host
                    .private_key_path
                    .as_deref()
                    .context("Private key path not configured")?;
                let key = russh_keys::load_secret_key(key_path, None)
                    .context("Failed to load private key")?;
                let auth_result = session
                    .authenticate_publickey(&host.username, Arc::new(key))
                    .await
                    .context("Public key authentication failed")?;
                if !auth_result {
                    anyhow::bail!("Public key authentication rejected by target host");
                }
            }
            "password" => {
                let password = host
                    .password
                    .as_deref()
                    .context("Password not configured for host")?;
                let pwd = password.strip_prefix("encrypted:").unwrap_or(password);
                let auth_result = session
                    .authenticate_password(&host.username, pwd)
                    .await
                    .context("Password authentication failed")?;
                if !auth_result {
                    anyhow::bail!("Password authentication rejected by target host");
                }
            }
            other => {
                anyhow::bail!("Unsupported auth method: {}", other);
            }
        }

        info!("Authenticated to target host (exec): {}", addr);

        // 打开 channel 并执行命令（无 PTY）
        let channel = session
            .channel_open_session()
            .await
            .context("Failed to open channel")?;

        let channel_id = channel.id();

        // 直接执行命令，不请求 PTY
        channel
            .exec(true, command)
            .await
            .context("Failed to exec command on target")?;

        Ok((
            Self {
                session,
                channel_id,
            },
            data_rx,
        ))
    }

    /// 连接到目标主机并启动 SFTP subsystem
    pub async fn connect_sftp(host: &HostEntry) -> Result<(Self, DataReceiver)> {
        let config = Arc::new(client::Config::default());
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let handler = ClientHandler { data_tx };

        let addr = format!("{}:{}", host.address, host.port);
        info!("Connecting to target host (sftp mode): {}", addr);

        let mut session = client::connect(config, &addr, handler)
            .await
            .context(format!("Failed to connect to {}", addr))?;

        // 认证
        match host.auth_method.as_str() {
            "key" => {
                let key_path = host
                    .private_key_path
                    .as_deref()
                    .context("Private key path not configured")?;
                let key = russh_keys::load_secret_key(key_path, None)
                    .context("Failed to load private key")?;
                let auth_result = session
                    .authenticate_publickey(&host.username, Arc::new(key))
                    .await
                    .context("Public key authentication failed")?;
                if !auth_result {
                    anyhow::bail!("Public key authentication rejected by target host");
                }
            }
            "password" => {
                let password = host
                    .password
                    .as_deref()
                    .context("Password not configured for host")?;
                let pwd = password.strip_prefix("encrypted:").unwrap_or(password);
                let auth_result = session
                    .authenticate_password(&host.username, pwd)
                    .await
                    .context("Password authentication failed")?;
                if !auth_result {
                    anyhow::bail!("Password authentication rejected by target host");
                }
            }
            other => {
                anyhow::bail!("Unsupported auth method: {}", other);
            }
        }

        info!("Authenticated to target host (sftp): {}", addr);

        // 打开 channel 并请求 sftp subsystem
        let channel = session
            .channel_open_session()
            .await
            .context("Failed to open channel")?;

        let channel_id = channel.id();

        // 请求 sftp subsystem
        channel
            .request_subsystem(true, "sftp")
            .await
            .context("Failed to request sftp subsystem")?;

        Ok((
            Self {
                session,
                channel_id,
            },
            data_rx,
        ))
    }

    /// 关闭连接
    pub async fn close(&self) -> Result<()> {
        self.session
            .disconnect(russh::Disconnect::ByApplication, "Session ended", "en")
            .await?;
        Ok(())
    }
}
