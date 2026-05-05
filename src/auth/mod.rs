pub mod acl;

use argon2::{Argon2, PasswordHash, PasswordVerifier};

use crate::config::{SecurityConfig, UserEntry};
use tracing::warn;

/// 用户认证器
pub struct Authenticator {
    users: Vec<UserEntry>,
    #[allow(dead_code)]
    max_auth_attempts: u32,
}

impl Authenticator {
    pub fn new(users: Vec<UserEntry>, security: &SecurityConfig) -> Self {
        Self {
            users,
            max_auth_attempts: security.max_auth_attempts,
        }
    }

    /// 验证密码
    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        let user = match self.users.iter().find(|u| u.name == username) {
            Some(u) => u,
            None => {
                warn!("User '{}' not found", username);
                return false;
            }
        };

        // 使用 argon2 验证密码哈希
        let parsed_hash = match PasswordHash::new(&user.password_hash) {
            Ok(h) => h,
            Err(e) => {
                warn!("Invalid password hash for '{}': {}", username, e);
                return false;
            }
        };

        match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    /// 验证公钥
    pub fn verify_public_key(&self, username: &str, key_base64: &str) -> bool {
        let user = match self.users.iter().find(|u| u.name == username) {
            Some(u) => u,
            None => {
                warn!("User '{}' not found for public key auth", username);
                return false;
            }
        };

        // 检查用户配置的公钥列表
        user.public_keys.iter().any(|k| {
            // 从 "ssh-rsa AAAA..." 格式中提取 base64 部分
            let parts: Vec<&str> = k.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[1] == key_base64
            } else {
                k == key_base64
            }
        })
    }

    /// 获取用户允许访问的主机列表
    pub fn get_allowed_hosts(&self, username: &str) -> Vec<String> {
        self.users
            .iter()
            .find(|u| u.name == username)
            .map(|u| u.allowed_hosts.clone())
            .unwrap_or_default()
    }
}
