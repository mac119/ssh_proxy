use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::info;

use crate::audit::AuditLogger;
use crate::client::SshClient;

/// 会话管理器
pub struct SessionManager {
    /// 活跃会话列表
    sessions: HashMap<String, SessionInfo>,
    /// 最大并发会话数
    max_sessions: usize,
}

/// 会话元数据
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub username: String,
    pub target_host: String,
    pub started_at: DateTime<Utc>,
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// 添加新会话
    pub fn add_session(&mut self, session_id: &str, username: &str, target_host: &str) -> bool {
        if self.sessions.len() >= self.max_sessions {
            return false;
        }

        let info = SessionInfo {
            session_id: session_id.to_string(),
            username: username.to_string(),
            target_host: target_host.to_string(),
            started_at: Utc::now(),
        };

        self.sessions.insert(session_id.to_string(), info);
        info!(
            "Session registered: {} (user={}, target={}). Active sessions: {}",
            session_id,
            username,
            target_host,
            self.sessions.len()
        );
        true
    }

    /// 移除会话
    pub fn remove_session(&mut self, session_id: &str) {
        if let Some(info) = self.sessions.remove(session_id) {
            let duration = Utc::now() - info.started_at;
            info!(
                "Session removed: {} (duration: {}s). Active sessions: {}",
                session_id,
                duration.num_seconds(),
                self.sessions.len()
            );
        }
    }

    /// 获取活跃会话数
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// 列出所有活跃会话
    pub fn list_sessions(&self) -> Vec<&SessionInfo> {
        self.sessions.values().collect()
    }
}

/// 代理会话：管理用户到目标主机的数据转发
pub struct ProxySession {
    session_id: String,
    username: String,
    target_host: String,
    client: SshClient,
    audit_logger: Arc<AuditLogger>,
}

impl ProxySession {
    pub fn new(
        session_id: String,
        username: String,
        target_host: String,
        client: SshClient,
        audit_logger: Arc<AuditLogger>,
    ) -> Self {
        Self {
            session_id,
            username,
            target_host,
            client,
            audit_logger,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 记录用户输入
    pub fn record_input(&self, data: &[u8]) {
        self.audit_logger
            .log_data(&self.session_id, "input", data);
    }

    /// 记录目标主机输出
    pub fn record_output(&self, data: &[u8]) {
        self.audit_logger
            .log_data(&self.session_id, "output", data);
    }

    /// 发送数据到目标主机
    pub async fn send_data(&self, data: &[u8]) -> anyhow::Result<()> {
        self.client.send_data(data).await
    }

    /// 发送 EOF 到目标主机
    pub async fn send_eof(&self) -> anyhow::Result<()> {
        self.client.send_eof().await
    }

    /// 关闭会话
    pub async fn close(&self) -> anyhow::Result<()> {
        self.client.close().await
    }
}
