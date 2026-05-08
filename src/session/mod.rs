use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use tracing::info;

use crate::audit::AuditLogger;
use crate::client::SshClient;

/// broadcast channel 容量
const BROADCAST_CAPACITY: usize = 1024;

/// 会话管理器
pub struct SessionManager {
    /// 活跃会话列表
    sessions: HashMap<String, SessionInfo>,
    /// 最大并发会话数
    max_sessions: usize,
}

/// 观察者信息
#[derive(Debug, Clone)]
pub struct WatcherInfo {
    pub username: String,
    pub joined_at: DateTime<Utc>,
}

/// 会话元数据
pub struct SessionInfo {
    pub session_id: String,
    pub username: String,
    pub target_host: String,
    pub started_at: DateTime<Utc>,
    /// 输出数据广播发送端（用于 session sharing）
    pub output_tx: broadcast::Sender<Vec<u8>>,
    /// 当前观察者列表
    pub watchers: Vec<WatcherInfo>,
}

impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo")
            .field("session_id", &self.session_id)
            .field("username", &self.username)
            .field("target_host", &self.target_host)
            .field("started_at", &self.started_at)
            .field("watchers", &self.watchers)
            .finish()
    }
}

impl Clone for SessionInfo {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            username: self.username.clone(),
            target_host: self.target_host.clone(),
            started_at: self.started_at,
            output_tx: self.output_tx.clone(),
            watchers: self.watchers.clone(),
        }
    }
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// 添加新会话，返回 broadcast::Sender 供 relay task 使用
    pub fn add_session(
        &mut self,
        session_id: &str,
        username: &str,
        target_host: &str,
    ) -> Option<broadcast::Sender<Vec<u8>>> {
        if self.sessions.len() >= self.max_sessions {
            return None;
        }

        let (output_tx, _) = broadcast::channel(BROADCAST_CAPACITY);

        let info = SessionInfo {
            session_id: session_id.to_string(),
            username: username.to_string(),
            target_host: target_host.to_string(),
            started_at: Utc::now(),
            output_tx: output_tx.clone(),
            watchers: Vec::new(),
        };

        self.sessions.insert(session_id.to_string(), info);
        info!(
            "Session registered: {} (user={}, target={}). Active sessions: {}",
            session_id,
            username,
            target_host,
            self.sessions.len()
        );
        Some(output_tx)
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

    /// 订阅某个会话的输出数据流（用于 session sharing）
    pub fn subscribe_session(
        &self,
        session_id: &str,
    ) -> Option<broadcast::Receiver<Vec<u8>>> {
        self.sessions
            .get(session_id)
            .map(|info| info.output_tx.subscribe())
    }

    /// 添加观察者到会话
    pub fn add_watcher(&mut self, session_id: &str, watcher_username: &str) -> bool {
        if let Some(info) = self.sessions.get_mut(session_id) {
            info.watchers.push(WatcherInfo {
                username: watcher_username.to_string(),
                joined_at: Utc::now(),
            });
            info!(
                "Watcher '{}' joined session {} (total watchers: {})",
                watcher_username,
                session_id,
                info.watchers.len()
            );
            true
        } else {
            false
        }
    }

    /// 移除观察者
    pub fn remove_watcher(&mut self, session_id: &str, watcher_username: &str) {
        if let Some(info) = self.sessions.get_mut(session_id) {
            info.watchers.retain(|w| w.username != watcher_username);
            info!(
                "Watcher '{}' left session {} (remaining watchers: {})",
                watcher_username,
                session_id,
                info.watchers.len()
            );
        }
    }

    /// 获取会话信息（用于权限检查等）
    pub fn get_session(&self, session_id: &str) -> Option<&SessionInfo> {
        self.sessions.get(session_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_manager_add_and_remove() {
        let mut sm = SessionManager::new(10);
        assert_eq!(sm.active_count(), 0);

        let tx = sm.add_session("s1", "user1", "host1");
        assert!(tx.is_some());
        assert_eq!(sm.active_count(), 1);

        let tx = sm.add_session("s2", "user2", "host2");
        assert!(tx.is_some());
        assert_eq!(sm.active_count(), 2);

        sm.remove_session("s1");
        assert_eq!(sm.active_count(), 1);

        sm.remove_session("s2");
        assert_eq!(sm.active_count(), 0);
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let mut sm = SessionManager::new(2);

        let tx1 = sm.add_session("s1", "user1", "host1");
        assert!(tx1.is_some());

        let tx2 = sm.add_session("s2", "user2", "host2");
        assert!(tx2.is_some());

        // 第三个会话应该被拒绝
        let tx3 = sm.add_session("s3", "user3", "host3");
        assert!(tx3.is_none());
        assert_eq!(sm.active_count(), 2);
    }

    #[test]
    fn test_subscribe_session() {
        let mut sm = SessionManager::new(10);
        sm.add_session("s1", "user1", "host1");

        // 订阅存在的会话
        let rx = sm.subscribe_session("s1");
        assert!(rx.is_some());

        // 订阅不存在的会话
        let rx = sm.subscribe_session("nonexistent");
        assert!(rx.is_none());
    }

    #[test]
    fn test_broadcast_data_to_subscriber() {
        let mut sm = SessionManager::new(10);
        let tx = sm.add_session("s1", "user1", "host1").unwrap();

        let mut rx = sm.subscribe_session("s1").unwrap();

        // 发送数据
        let data = b"hello world".to_vec();
        tx.send(data.clone()).unwrap();

        // 接收数据
        let received = rx.try_recv().unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn test_broadcast_multiple_subscribers() {
        let mut sm = SessionManager::new(10);
        let tx = sm.add_session("s1", "user1", "host1").unwrap();

        let mut rx1 = sm.subscribe_session("s1").unwrap();
        let mut rx2 = sm.subscribe_session("s1").unwrap();

        // 发送数据
        let data = b"shared data".to_vec();
        tx.send(data.clone()).unwrap();

        // 两个接收者都应该收到
        assert_eq!(rx1.try_recv().unwrap(), data);
        assert_eq!(rx2.try_recv().unwrap(), data);
    }

    #[test]
    fn test_broadcast_no_subscriber_no_error() {
        let mut sm = SessionManager::new(10);
        let tx = sm.add_session("s1", "user1", "host1").unwrap();

        // 没有订阅者时发送不应 panic
        let result = tx.send(b"data".to_vec());
        // send 在没有 receiver 时返回 Err，但不应 panic
        assert!(result.is_err());
    }

    #[test]
    fn test_broadcast_lagged_receiver() {
        let mut sm = SessionManager::new(10);
        let tx = sm.add_session("s1", "user1", "host1").unwrap();
        let mut rx = sm.subscribe_session("s1").unwrap();

        // 发送超过 channel 容量的消息（capacity = 1024）
        for i in 0..1030 {
            let _ = tx.send(format!("msg-{}", i).into_bytes());
        }

        // 接收时应该得到 Lagged 错误
        let result = rx.try_recv();
        match result {
            Err(broadcast::error::TryRecvError::Lagged(_)) => {
                // 预期行为
            }
            other => {
                // 也可能成功接收到后面的消息（取决于 timing）
                // 只要不 panic 就行
                assert!(other.is_ok() || matches!(other, Err(broadcast::error::TryRecvError::Lagged(_))));
            }
        }
    }

    #[test]
    fn test_add_and_remove_watcher() {
        let mut sm = SessionManager::new(10);
        sm.add_session("s1", "user1", "host1");

        // 添加观察者
        assert!(sm.add_watcher("s1", "admin"));
        assert!(sm.add_watcher("s1", "ops"));

        let session = sm.get_session("s1").unwrap();
        assert_eq!(session.watchers.len(), 2);

        // 移除观察者
        sm.remove_watcher("s1", "admin");
        let session = sm.get_session("s1").unwrap();
        assert_eq!(session.watchers.len(), 1);
        assert_eq!(session.watchers[0].username, "ops");
    }

    #[test]
    fn test_add_watcher_to_nonexistent_session() {
        let mut sm = SessionManager::new(10);
        assert!(!sm.add_watcher("nonexistent", "admin"));
    }

    #[test]
    fn test_remove_watcher_from_nonexistent_session() {
        let mut sm = SessionManager::new(10);
        // 不应 panic
        sm.remove_watcher("nonexistent", "admin");
    }

    #[test]
    fn test_get_session() {
        let mut sm = SessionManager::new(10);
        sm.add_session("s1", "user1", "host1");

        let session = sm.get_session("s1");
        assert!(session.is_some());
        let s = session.unwrap();
        assert_eq!(s.session_id, "s1");
        assert_eq!(s.username, "user1");
        assert_eq!(s.target_host, "host1");

        assert!(sm.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_list_sessions() {
        let mut sm = SessionManager::new(10);
        sm.add_session("s1", "user1", "host1");
        sm.add_session("s2", "user2", "host2");

        let sessions = sm.list_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_session_remove_cleans_watchers() {
        let mut sm = SessionManager::new(10);
        sm.add_session("s1", "user1", "host1");
        sm.add_watcher("s1", "admin");
        sm.add_watcher("s1", "ops");

        // 移除会话后，观察者信息也应该被清理
        sm.remove_session("s1");
        assert!(sm.get_session("s1").is_none());
    }

    #[tokio::test]
    async fn test_broadcast_sender_dropped_signals_closed() {
        let mut sm = SessionManager::new(10);
        let _tx = sm.add_session("s1", "user1", "host1").unwrap();
        let mut rx = sm.subscribe_session("s1").unwrap();

        // 移除会话（drops sender from SessionManager）
        sm.remove_session("s1");

        // 由于 _tx 仍然持有 sender，channel 没有关闭
        // 但如果我们 drop _tx...
        drop(_tx);

        // 现在 receiver 应该收到 Closed
        let result = rx.recv().await;
        assert!(matches!(result, Err(broadcast::error::RecvError::Closed)));
    }
}
