pub mod recorder;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::info;

/// 审计事件类型
#[derive(Debug, Serialize)]
#[serde(tag = "event")]
pub enum AuditEvent {
    #[serde(rename = "auth_success")]
    AuthSuccess {
        timestamp: String,
        user: String,
        peer_addr: String,
        method: String,
    },
    #[serde(rename = "auth_failure")]
    AuthFailure {
        timestamp: String,
        user: String,
        peer_addr: String,
        method: String,
    },
    #[serde(rename = "session_start")]
    SessionStart {
        timestamp: String,
        session_id: String,
        user: String,
        peer_addr: String,
        target_host: String,
        target_addr: String,
    },
    #[serde(rename = "session_end")]
    SessionEnd {
        timestamp: String,
        session_id: String,
    },
    #[serde(rename = "data")]
    Data {
        timestamp: String,
        session_id: String,
        direction: String,
        data_base64: String,
        data_len: usize,
    },
    #[serde(rename = "command_blocked")]
    CommandBlocked {
        timestamp: String,
        session_id: String,
        user: String,
        command: String,
        reason: String,
    },
    #[serde(rename = "scp_session_start")]
    ScpSessionStart {
        timestamp: String,
        session_id: String,
        user: String,
        peer_addr: String,
        target_host: String,
        direction: String,
        remote_path: String,
    },
    #[serde(rename = "scp_file_transfer")]
    ScpFileTransfer {
        timestamp: String,
        session_id: String,
        user: String,
        direction: String,
        filename: String,
        size: u64,
        mode: String,
    },
    #[serde(rename = "session_watch_start")]
    SessionWatchStart {
        timestamp: String,
        watcher: String,
        target_session_id: String,
        target_user: String,
        target_host: String,
    },
    #[serde(rename = "session_watch_end")]
    SessionWatchEnd {
        timestamp: String,
        watcher: String,
        target_session_id: String,
        duration_secs: i64,
    },
}

/// 审计日志记录器
pub struct AuditLogger {
    log_dir: PathBuf,
    /// 主审计日志文件互斥锁
    log_file: Mutex<fs::File>,
}

impl AuditLogger {
    pub fn new(log_dir: &str) -> Result<Self> {
        let log_path = Path::new(log_dir);
        fs::create_dir_all(log_path)?;

        let audit_file_path = log_path.join("audit.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_file_path)?;

        info!("Audit log file: {:?}", audit_file_path);

        Ok(Self {
            log_dir: log_path.to_path_buf(),
            log_file: Mutex::new(file),
        })
    }

    /// 写入审计事件
    fn write_event(&self, event: &AuditEvent) {
        let json = match serde_json::to_string(event) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize audit event: {}", e);
                return;
            }
        };

        if let Ok(mut file) = self.log_file.lock() {
            let _ = writeln!(file, "{}", json);
        }
    }

    /// 记录认证成功
    pub fn log_auth_success(&self, user: &str, peer_addr: &str, method: &str) {
        let event = AuditEvent::AuthSuccess {
            timestamp: Utc::now().to_rfc3339(),
            user: user.to_string(),
            peer_addr: peer_addr.to_string(),
            method: method.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录认证失败
    pub fn log_auth_failure(&self, user: &str, peer_addr: &str, method: &str) {
        let event = AuditEvent::AuthFailure {
            timestamp: Utc::now().to_rfc3339(),
            user: user.to_string(),
            peer_addr: peer_addr.to_string(),
            method: method.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录会话开始
    pub fn log_session_start(
        &self,
        session_id: &str,
        user: &str,
        peer_addr: &str,
        target_host: &str,
        target_addr: &str,
    ) {
        let event = AuditEvent::SessionStart {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            peer_addr: peer_addr.to_string(),
            target_host: target_host.to_string(),
            target_addr: target_addr.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录会话结束
    pub fn log_session_end(&self, session_id: &str) {
        let event = AuditEvent::SessionEnd {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录数据传输
    pub fn log_data(&self, session_id: &str, direction: &str, data: &[u8]) {
        use base64::Engine;
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(data);
        let event = AuditEvent::Data {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            direction: direction.to_string(),
            data_base64,
            data_len: data.len(),
        };
        self.write_event(&event);
    }

    /// 记录命令被拦截
    pub fn log_command_blocked(&self, session_id: &str, user: &str, command: &str, reason: &str) {
        let event = AuditEvent::CommandBlocked {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            command: command.to_string(),
            reason: reason.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录 SCP 会话开始
    pub fn log_scp_session_start(
        &self,
        session_id: &str,
        user: &str,
        peer_addr: &str,
        target_host: &str,
        direction: &str,
        remote_path: &str,
    ) {
        let event = AuditEvent::ScpSessionStart {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            peer_addr: peer_addr.to_string(),
            target_host: target_host.to_string(),
            direction: direction.to_string(),
            remote_path: remote_path.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录 SCP 文件传输
    pub fn log_scp_file_transfer(
        &self,
        session_id: &str,
        user: &str,
        direction: &str,
        filename: &str,
        size: u64,
        mode: &str,
    ) {
        let event = AuditEvent::ScpFileTransfer {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            direction: direction.to_string(),
            filename: filename.to_string(),
            size,
            mode: mode.to_string(),
        };
        self.write_event(&event);
    }

    /// 获取会话日志目录（用于会话录制）
    pub fn session_log_dir(&self, session_id: &str) -> PathBuf {
        let dir = self.log_dir.join("sessions").join(session_id);
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// 记录观察会话开始
    pub fn log_session_watch_start(
        &self,
        watcher: &str,
        target_session_id: &str,
        target_user: &str,
        target_host: &str,
    ) {
        let event = AuditEvent::SessionWatchStart {
            timestamp: Utc::now().to_rfc3339(),
            watcher: watcher.to_string(),
            target_session_id: target_session_id.to_string(),
            target_user: target_user.to_string(),
            target_host: target_host.to_string(),
        };
        self.write_event(&event);
    }

    /// 记录观察会话结束
    pub fn log_session_watch_end(
        &self,
        watcher: &str,
        target_session_id: &str,
        duration_secs: i64,
    ) {
        let event = AuditEvent::SessionWatchEnd {
            timestamp: Utc::now().to_rfc3339(),
            watcher: watcher.to_string(),
            target_session_id: target_session_id.to_string(),
            duration_secs,
        };
        self.write_event(&event);
    }
}
