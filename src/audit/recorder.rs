use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use serde::Serialize;
use tracing::info;

/// Asciicast v2 格式的会话录制器
/// 兼容 asciinema 播放器进行回放
pub struct SessionRecorder {
    file: File,
    start_time: f64,
}

/// Asciicast v2 header
#[derive(Serialize)]
struct AsciicastHeader {
    version: u8,
    width: u32,
    height: u32,
    timestamp: i64,
    title: String,
    env: AsciicastEnv,
}

#[derive(Serialize)]
struct AsciicastEnv {
    #[serde(rename = "SHELL")]
    shell: String,
    #[serde(rename = "TERM")]
    term: String,
}

impl SessionRecorder {
    /// 创建新的会话录制器
    pub fn new(
        log_dir: &PathBuf,
        session_id: &str,
        username: &str,
        target_host: &str,
        width: u32,
        height: u32,
    ) -> anyhow::Result<Self> {
        let file_path = log_dir.join(format!("{}.cast", session_id));
        let mut file = File::create(&file_path)?;

        let now = Utc::now();
        let header = AsciicastHeader {
            version: 2,
            width,
            height,
            timestamp: now.timestamp(),
            title: format!("{}@{}", username, target_host),
            env: AsciicastEnv {
                shell: "/bin/bash".to_string(),
                term: "xterm-256color".to_string(),
            },
        };

        // 写入 header
        let header_json = serde_json::to_string(&header)?;
        writeln!(file, "{}", header_json)?;

        let start_time = now.timestamp_millis() as f64 / 1000.0;

        info!("Session recording started: {:?}", file_path);

        Ok(Self { file, start_time })
    }

    /// 记录输出事件
    pub fn record_output(&mut self, data: &[u8]) {
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let elapsed = now - self.start_time;

        let text = String::from_utf8_lossy(data);
        let event = format!(
            "[{:.6}, \"o\", {}]",
            elapsed,
            serde_json::to_string(&text.as_ref()).unwrap_or_default()
        );

        let _ = writeln!(self.file, "{}", event);
    }

    /// 记录输入事件
    pub fn record_input(&mut self, data: &[u8]) {
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let elapsed = now - self.start_time;

        let text = String::from_utf8_lossy(data);
        let event = format!(
            "[{:.6}, \"i\", {}]",
            elapsed,
            serde_json::to_string(&text.as_ref()).unwrap_or_default()
        );

        let _ = writeln!(self.file, "{}", event);
    }
}
