use async_trait::async_trait;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, Pty};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::audit::AuditLogger;
use crate::auth::Authenticator;
use crate::client::SshClient;
use crate::config::AppConfig;
use crate::session::{ProxySession, SessionManager};

/// 每个客户端连接的处理器
pub struct ProxyHandler {
    peer_addr: String,
    authenticator: Arc<Authenticator>,
    session_manager: Arc<Mutex<SessionManager>>,
    audit_logger: Arc<AuditLogger>,
    app_config: Arc<AppConfig>,
    /// 认证后的用户名
    username: Option<String>,
    /// 当前活跃的代理会话
    proxy_session: Option<Arc<Mutex<ProxySession>>>,
    /// 是否已连接到目标主机
    connected_to_target: bool,
    /// 目标主机选择阶段的输入缓冲
    input_buffer: String,
    /// 用户 channel ID（用于后台转发任务）
    user_channel_id: Option<ChannelId>,
}

impl ProxyHandler {
    pub fn new(
        peer_addr: String,
        authenticator: Arc<Authenticator>,
        session_manager: Arc<Mutex<SessionManager>>,
        audit_logger: Arc<AuditLogger>,
        app_config: Arc<AppConfig>,
    ) -> Self {
        Self {
            peer_addr,
            authenticator,
            session_manager,
            audit_logger,
            app_config,
            username: None,
            proxy_session: None,
            connected_to_target: false,
            input_buffer: String::new(),
            user_channel_id: None,
        }
    }

    /// 发送可用主机列表给用户
    async fn send_host_menu(&self, session: &mut Session, channel: ChannelId) {
        let username = self.username.as_deref().unwrap_or("unknown");
        let allowed_hosts = self.authenticator.get_allowed_hosts(username);

        let mut menu = format!("\r\nWelcome, {}! Available hosts:\r\n", username);
        menu.push_str("─────────────────────────────────────\r\n");

        let mut idx = 1;
        for host in &self.app_config.hosts {
            if allowed_hosts.contains(&"*".to_string()) || allowed_hosts.contains(&host.name) {
                menu.push_str(&format!(
                    "  [{}] {} ({}:{})\r\n",
                    idx, host.name, host.address, host.port
                ));
                idx += 1;
            }
        }

        menu.push_str("─────────────────────────────────────\r\n");
        menu.push_str("Select host number: ");

        session.data(channel, CryptoVec::from(menu.as_bytes().to_vec()));
    }

    /// 处理目标主机选择
    async fn handle_host_selection(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        selection: &str,
    ) -> bool {
        let username = self.username.as_deref().unwrap_or("unknown");
        let allowed_hosts = self.authenticator.get_allowed_hosts(username);

        // 筛选可用主机
        let available: Vec<_> = self
            .app_config
            .hosts
            .iter()
            .filter(|h| allowed_hosts.contains(&"*".to_string()) || allowed_hosts.contains(&h.name))
            .collect();

        let selection = selection.trim();
        let idx: usize = match selection.parse::<usize>() {
            Ok(n) if n >= 1 && n <= available.len() => n - 1,
            _ => {
                let msg = format!("\r\nInvalid selection: '{}'. Please try again: ", selection);
                session.data(channel, CryptoVec::from(msg.as_bytes().to_vec()));
                return false;
            }
        };

        let target_host = available[idx].clone();
        info!(
            "User '{}' selected host '{}' ({}:{})",
            username, target_host.name, target_host.address, target_host.port
        );

        // 记录审计日志
        let session_id = uuid::Uuid::new_v4().to_string();
        self.audit_logger.log_session_start(
            &session_id,
            username,
            &self.peer_addr,
            &target_host.name,
            &target_host.address,
        );

        // 连接目标主机
        let connecting_msg = format!("\r\nConnecting to {} ...\r\n", target_host.name);
        session.data(channel, CryptoVec::from(connecting_msg.as_bytes().to_vec()));

        match SshClient::connect(&target_host).await {
            Ok((client, mut data_rx)) => {
                let connected_msg = format!("Connected to {}. Session started.\r\n\r\n", target_host.name);
                session.data(channel, CryptoVec::from(connected_msg.as_bytes().to_vec()));

                let proxy_session = ProxySession::new(
                    session_id.clone(),
                    username.to_string(),
                    target_host.name.clone(),
                    client,
                    self.audit_logger.clone(),
                );

                let proxy_session = Arc::new(Mutex::new(proxy_session));
                self.proxy_session = Some(proxy_session.clone());
                self.connected_to_target = true;

                // 注册会话
                let mut sm = self.session_manager.lock().await;
                sm.add_session(&session_id, username, &target_host.name);
                drop(sm);

                // 启动后台任务：从目标主机读取数据并转发给用户
                let server_handle = session.handle();
                let audit_logger = self.audit_logger.clone();
                let sid = session_id.clone();

                tokio::spawn(async move {
                    while let Some(data) = data_rx.recv().await {
                        // 记录输出到审计日志
                        audit_logger.log_data(&sid, "output", &data);

                        // 转发数据给用户
                        if let Err(e) = server_handle
                            .data(channel, CryptoVec::from(data))
                            .await
                        {
                            error!("Failed to send data to user: {:?}", e);
                            break;
                        }
                    }
                    info!("Data forwarding task ended for session {}", sid);
                });

                true
            }
            Err(e) => {
                error!("Failed to connect to {}: {}", target_host.name, e);
                let err_msg = format!("\r\nFailed to connect to {}: {}\r\n", target_host.name, e);
                session.data(channel, CryptoVec::from(err_msg.as_bytes().to_vec()));
                false
            }
        }
    }
}

#[async_trait]
impl Handler for ProxyHandler {
    type Error = anyhow::Error;

    /// 密码认证
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        info!("Password auth attempt for user '{}' from {}", user, self.peer_addr);

        if self.authenticator.verify_password(user, password) {
            info!("User '{}' authenticated successfully", user);
            self.username = Some(user.to_string());
            self.audit_logger.log_auth_success(user, &self.peer_addr, "password");
            Ok(Auth::Accept)
        } else {
            warn!("Authentication failed for user '{}' from {}", user, self.peer_addr);
            self.audit_logger.log_auth_failure(user, &self.peer_addr, "password");
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    /// 公钥认证
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        info!("Public key auth attempt for user '{}' from {}", user, self.peer_addr);

        let key_str = russh_keys::PublicKeyBase64::public_key_base64(public_key);
        if self.authenticator.verify_public_key(user, &key_str) {
            info!("User '{}' authenticated via public key", user);
            self.username = Some(user.to_string());
            self.audit_logger.log_auth_success(user, &self.peer_addr, "publickey");
            Ok(Auth::Accept)
        } else {
            warn!("Public key auth failed for user '{}' from {}", user, self.peer_addr);
            self.audit_logger.log_auth_failure(user, &self.peer_addr, "publickey");
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    /// 处理 channel open 请求
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!("Channel open session request from user '{:?}'", self.username);
        self.user_channel_id = Some(channel.id());
        Ok(true)
    }

    /// 处理 PTY 请求
    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("PTY request: term={}, cols={}, rows={}", term, col_width, row_height);
        session.request_success();
        Ok(())
    }

    /// 处理 shell 请求
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Shell request from user '{:?}'", self.username);
        session.request_success();

        // 发送主机选择菜单
        self.send_host_menu(session, channel).await;
        Ok(())
    }

    /// 处理客户端发送的数据
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.connected_to_target {
            // 已连接目标主机，转发数据到目标
            if let Some(proxy_session) = &self.proxy_session {
                let ps = proxy_session.lock().await;
                // 记录输入到审计日志
                ps.record_input(data);
                // 转发到目标主机
                if let Err(e) = ps.send_data(data).await {
                    error!("Failed to forward data to target: {}", e);
                    let msg = format!("\r\nConnection to target lost: {}\r\n", e);
                    session.data(channel, CryptoVec::from(msg.as_bytes().to_vec()));
                    session.close(channel);
                }
            }
        } else {
            // 主机选择阶段：收集用户输入
            for &byte in data {
                match byte {
                    b'\r' | b'\n' => {
                        let input = self.input_buffer.clone();
                        self.input_buffer.clear();
                        session.data(channel, CryptoVec::from(b"\r\n".to_vec()));
                        self.handle_host_selection(session, channel, &input).await;
                    }
                    127 | 8 => {
                        // Backspace
                        if !self.input_buffer.is_empty() {
                            self.input_buffer.pop();
                            session.data(channel, CryptoVec::from(b"\x08 \x08".to_vec()));
                        }
                    }
                    3 => {
                        // Ctrl+C
                        info!("User pressed Ctrl+C during host selection");
                        session.close(channel);
                    }
                    _ => {
                        self.input_buffer.push(byte as char);
                        session.data(channel, CryptoVec::from(vec![byte]));
                    }
                }
            }
        }

        Ok(())
    }

    /// 连接关闭时清理
    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Channel closed for user '{:?}'", self.username);

        if let Some(proxy_session) = self.proxy_session.take() {
            let ps = proxy_session.lock().await;
            let session_id = ps.session_id().to_string();

            // 记录会话结束
            self.audit_logger.log_session_end(&session_id);

            // 移除会话
            let mut sm = self.session_manager.lock().await;
            sm.remove_session(&session_id);
        }

        Ok(())
    }
}
