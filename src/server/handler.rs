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
use crate::filter::{CommandFilter, FilterAction};
use crate::scp::{self, ScpParser};
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
    /// 命令行缓冲（用于命令过滤）
    command_buffer: String,
    /// 用户 channel ID（用于后台转发任务）
    user_channel_id: Option<ChannelId>,
    /// 命令过滤器
    command_filter: Option<CommandFilter>,
    /// 是否处于交互模式（vi/nano等），暂停过滤
    interactive_mode: bool,
    /// SCP 解析器（当检测到 SCP 传输时）
    scp_parser: Option<Arc<Mutex<ScpParser>>>,
    /// 是否为 SCP/exec 模式的连接（非交互式）
    is_exec_mode: bool,
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
            command_buffer: String::new(),
            user_channel_id: None,
            command_filter: None,
            interactive_mode: false,
            scp_parser: None,
            is_exec_mode: false,
        }
    }

    /// 初始化命令过滤器（认证成功后调用）
    fn init_command_filter(&mut self, username: &str) {
        if let Some(user) = self.app_config.users.iter().find(|u| u.name == username) {
            let filter = CommandFilter::from_user_config(user);
            if filter.is_enabled() {
                info!(
                    "Command filter enabled for user '{}': mode={}",
                    username, user.command_filter_mode
                );
            }
            self.command_filter = Some(filter);
        }
    }

    /// 检测是否进入/退出交互模式的命令
    fn check_interactive_command(&mut self, cmd: &str) {
        let cmd_name = cmd.trim().split_whitespace().next().unwrap_or("");
        let interactive_commands = ["vi", "vim", "nvim", "nano", "emacs", "less", "more", "top", "htop", "man"];

        if interactive_commands.iter().any(|&ic| cmd_name == ic) {
            self.interactive_mode = true;
            info!("Entering interactive mode (command: {})", cmd_name);
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

    /// 处理已连接状态下的数据（含命令过滤）
    async fn handle_connected_data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) {
        // 检查是否有命令过滤器且不处于交互模式
        let should_filter = self.command_filter.as_ref()
            .map(|f| f.is_enabled())
            .unwrap_or(false) && !self.interactive_mode;

        if !should_filter {
            // 不需要过滤，直接转发
            self.forward_data_to_target(data, channel, session).await;
            return;
        }

        // 需要命令过滤：逐字节处理
        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    // 用户按下回车，检查命令
                    let command = self.command_buffer.clone();
                    self.command_buffer.clear();

                    if command.trim().is_empty() {
                        // 空命令，直接转发回车
                        self.forward_data_to_target(&[byte], channel, session).await;
                        continue;
                    }

                    // 检查命令是否允许
                    let action = self.command_filter.as_ref()
                        .map(|f| f.check_command(&command))
                        .unwrap_or(FilterAction::Allow);

                    match action {
                        FilterAction::Allow => {
                            // 检查是否是交互式命令
                            self.check_interactive_command(&command);

                            // 命令允许，转发整个命令行 + 回车
                            // 注意：命令已经在用户输入时逐字节回显并转发了
                            // 这里只需要转发回车
                            self.forward_data_to_target(&[byte], channel, session).await;
                        }
                        FilterAction::Block(reason) => {
                            // 命令被拦截
                            let username = self.username.as_deref().unwrap_or("unknown");
                            warn!(
                                "Command BLOCKED for user '{}': '{}'",
                                username, command
                            );

                            // 记录到审计日志
                            if let Some(proxy_session) = &self.proxy_session {
                                let ps = proxy_session.lock().await;
                                self.audit_logger.log_command_blocked(
                                    ps.session_id(),
                                    username,
                                    &command,
                                    &reason,
                                );
                            }

                            // 发送拒绝消息给用户（模拟 shell 输出）
                            let block_msg = format!(
                                "\r\n\x1b[1;31m⛔ BLOCKED:\x1b[0m {}\r\n",
                                reason
                            );
                            session.data(channel, CryptoVec::from(block_msg.as_bytes().to_vec()));

                            // 发送一个新的提示符（模拟回到 shell）
                            // 通过发送 Ctrl+C 到目标主机来取消当前行
                            self.forward_data_to_target(b"\x03", channel, session).await;
                        }
                    }
                }
                // Ctrl+C: 清空命令缓冲并直接转发
                3 => {
                    self.command_buffer.clear();
                    // 如果在交互模式下退出
                    if self.interactive_mode {
                        self.interactive_mode = false;
                    }
                    self.forward_data_to_target(&[byte], channel, session).await;
                }
                // Backspace / DEL
                127 | 8 => {
                    self.command_buffer.pop();
                    self.forward_data_to_target(&[byte], channel, session).await;
                }
                // Escape sequences (arrow keys etc.) - pass through but don't add to buffer
                27 => {
                    self.forward_data_to_target(&[byte], channel, session).await;
                }
                // Regular character
                _ => {
                    // Only add printable ASCII to command buffer
                    if byte >= 32 && byte < 127 {
                        self.command_buffer.push(byte as char);
                    }
                    self.forward_data_to_target(&[byte], channel, session).await;
                }
            }
        }
    }

    /// 转发数据到目标主机
    async fn forward_data_to_target(
        &self,
        data: &[u8],
        channel: ChannelId,
        session: &mut Session,
    ) {
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
    }

    /// 为 exec/SCP 模式解析目标主机
    /// 策略：使用用户允许列表中的第一个主机（后续可通过用户名格式指定）
    fn resolve_target_host_for_exec(&self, username: &str) -> Option<crate::config::HostEntry> {
        let allowed_hosts = self.authenticator.get_allowed_hosts(username);

        // 检查用户名是否包含目标主机标识（格式: user%hostname）
        // 例如: admin%db-server-01
        let target_name = if let Some(user) = &self.username {
            if let Some((_user_part, host_part)) = user.split_once('%') {
                Some(host_part.to_string())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(target) = target_name {
            // 查找指定的目标主机
            self.app_config.hosts.iter().find(|h| {
                h.name == target
                    && (allowed_hosts.contains(&"*".to_string())
                        || allowed_hosts.contains(&h.name))
            }).cloned()
        } else {
            // 默认使用第一个允许的主机
            self.app_config.hosts.iter().find(|h| {
                allowed_hosts.contains(&"*".to_string()) || allowed_hosts.contains(&h.name)
            }).cloned()
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
            self.init_command_filter(user);
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
            self.init_command_filter(user);
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

    /// 处理 exec 请求（SCP 和其他远程命令走这里）
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        let username = self.username.as_deref().unwrap_or("unknown").to_string();

        info!("Exec request from user '{}': {}", username, command);

        // 检查是否是 SCP 命令
        if let Some(scp_cmd) = scp::parse_scp_command(&command) {
            info!(
                "SCP transfer detected: user='{}', direction={}, path='{}', recursive={}",
                username, scp_cmd.direction, scp_cmd.remote_path, scp_cmd.recursive
            );

            // 确定目标主机（使用用户允许的第一个主机，或通过配置指定）
            let target_host = self.resolve_target_host_for_exec(&username);

            match target_host {
                Some(host) => {
                    let session_id = uuid::Uuid::new_v4().to_string();

                    // 记录 SCP 会话开始
                    self.audit_logger.log_scp_session_start(
                        &session_id,
                        &username,
                        &self.peer_addr,
                        &host.name,
                        &scp_cmd.direction.to_string(),
                        &scp_cmd.remote_path,
                    );

                    session.request_success();
                    self.is_exec_mode = true;

                    // 创建 SCP 解析器
                    let parser = ScpParser::new(&scp_cmd);
                    let parser = Arc::new(Mutex::new(parser));
                    self.scp_parser = Some(parser.clone());

                    // 连接到目标主机（exec 模式）
                    match SshClient::connect_exec(&host, &command).await {
                        Ok((client, mut data_rx)) => {
                            info!("SCP connection established to {}", host.name);

                            // 创建简化的代理会话
                            let proxy_session = ProxySession::new(
                                session_id.clone(),
                                username.clone(),
                                host.name.clone(),
                                client,
                                self.audit_logger.clone(),
                            );
                            let proxy_session = Arc::new(Mutex::new(proxy_session));
                            self.proxy_session = Some(proxy_session);
                            self.connected_to_target = true;

                            // 启动后台任务：从目标主机读取数据并转发给用户
                            // 对于 SCP download，解析从目标主机来的数据流
                            let server_handle = session.handle();
                            let audit_logger = self.audit_logger.clone();
                            let sid = session_id.clone();
                            let scp_parser_clone = parser.clone();
                            let scp_direction = scp_cmd.direction.clone();
                            let user_clone = username.clone();

                            tokio::spawn(async move {
                                while let Some(data) = data_rx.recv().await {
                                    // 如果是下载方向，解析目标主机发来的数据
                                    if scp_direction == scp::ScpDirection::Download {
                                        let mut p = scp_parser_clone.lock().await;
                                        let new_files = p.parse_data(&data);
                                        for file in new_files {
                                            info!(
                                                "SCP download file: {} ({} bytes)",
                                                file.filename, file.size
                                            );
                                            audit_logger.log_scp_file_transfer(
                                                &sid,
                                                &user_clone,
                                                &file.direction.to_string(),
                                                &file.filename,
                                                file.size,
                                                &file.mode,
                                            );
                                        }
                                    }

                                    // 转发数据给用户
                                    if let Err(e) = server_handle
                                        .data(channel, CryptoVec::from(data))
                                        .await
                                    {
                                        error!("Failed to send data to user: {:?}", e);
                                        break;
                                    }
                                }
                                info!("SCP data forwarding ended for session {}", sid);
                                audit_logger.log_session_end(&sid);
                            });
                        }
                        Err(e) => {
                            error!("Failed to connect to {} for SCP: {}", host.name, e);
                            session.close(channel);
                        }
                    }
                }
                None => {
                    warn!("No target host resolved for SCP exec from user '{}'", username);
                    let msg = b"Error: No target host configured for SCP transfer.\n";
                    session.data(channel, CryptoVec::from(msg.to_vec()));
                    session.close(channel);
                }
            }
        } else {
            // 非 SCP 的 exec 命令 — 可以选择拒绝或转发
            warn!("Non-SCP exec request from '{}': {}", username, command);
            let msg = format!(
                "Error: Direct exec commands are not supported. Use interactive shell.\n"
            );
            session.data(channel, CryptoVec::from(msg.as_bytes().to_vec()));
            session.close(channel);
        }

        Ok(())
    }

    /// 处理 subsystem 请求（SFTP 走这里）
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let username = self.username.as_deref().unwrap_or("unknown").to_string();
        info!("Subsystem request from user '{}': {}", username, name);

        if name == "sftp" {
            // 确定目标主机
            let target_host = self.resolve_target_host_for_exec(&username);

            match target_host {
                Some(host) => {
                    let session_id = uuid::Uuid::new_v4().to_string();

                    self.audit_logger.log_scp_session_start(
                        &session_id,
                        &username,
                        &self.peer_addr,
                        &host.name,
                        "sftp",
                        "",
                    );

                    session.request_success();
                    self.is_exec_mode = true;

                    // 连接到目标主机并请求 sftp subsystem
                    // 使用 exec 模式执行 "sftp-server" 或通过 subsystem
                    match SshClient::connect_sftp(&host).await {
                        Ok((client, mut data_rx)) => {
                            info!("SFTP connection established to {}", host.name);

                            let proxy_session = ProxySession::new(
                                session_id.clone(),
                                username.clone(),
                                host.name.clone(),
                                client,
                                self.audit_logger.clone(),
                            );
                            let proxy_session = Arc::new(Mutex::new(proxy_session));
                            self.proxy_session = Some(proxy_session);
                            self.connected_to_target = true;

                            // 启动后台任务：从目标主机读取 SFTP 数据并转发给用户
                            let server_handle = session.handle();
                            let audit_logger = self.audit_logger.clone();
                            let sid = session_id.clone();

                            tokio::spawn(async move {
                                while let Some(data) = data_rx.recv().await {
                                    audit_logger.log_data(&sid, "sftp_output", &data);
                                    if let Err(e) = server_handle
                                        .data(channel, CryptoVec::from(data))
                                        .await
                                    {
                                        error!("Failed to send SFTP data to user: {:?}", e);
                                        break;
                                    }
                                }
                                info!("SFTP forwarding ended for session {}", sid);
                                audit_logger.log_session_end(&sid);
                            });
                        }
                        Err(e) => {
                            error!("Failed to connect to {} for SFTP: {}", host.name, e);
                            session.close(channel);
                        }
                    }
                }
                None => {
                    warn!("No target host resolved for SFTP from user '{}'", username);
                    session.close(channel);
                }
            }
        } else {
            warn!("Unsupported subsystem '{}' from user '{}'", name, username);
            session.close(channel);
        }

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
            if self.is_exec_mode {
                // SCP/exec 模式：直接转发，但对上传方向做解析
                if let Some(scp_parser) = &self.scp_parser {
                    let mut parser = scp_parser.lock().await;
                    if parser.direction == scp::ScpDirection::Upload {
                        let new_files = parser.parse_data(data);
                        let session_id = if let Some(ps) = &self.proxy_session {
                            let ps = ps.lock().await;
                            ps.session_id().to_string()
                        } else {
                            String::new()
                        };
                        let username = self.username.as_deref().unwrap_or("unknown");

                        for file in new_files {
                            info!(
                                "SCP upload file: {} ({} bytes)",
                                file.filename, file.size
                            );
                            self.audit_logger.log_scp_file_transfer(
                                &session_id,
                                username,
                                &file.direction.to_string(),
                                &file.filename,
                                file.size,
                                &file.mode,
                            );
                        }
                    }
                    drop(parser);
                }

                // 转发数据到目标主机
                self.forward_data_to_target(data, channel, session).await;
            } else {
                // 交互式 shell 模式：使用命令过滤逻辑
                self.handle_connected_data(channel, data, session).await;
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
