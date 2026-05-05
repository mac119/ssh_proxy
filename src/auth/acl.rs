use crate::config::HostEntry;

/// ACL (Access Control List) 检查
pub struct AclChecker;

impl AclChecker {
    /// 检查用户是否有权访问指定主机
    pub fn check_access(allowed_hosts: &[String], target_host: &str) -> bool {
        // 通配符 "*" 表示允许访问所有主机
        if allowed_hosts.contains(&"*".to_string()) {
            return true;
        }
        allowed_hosts.contains(&target_host.to_string())
    }

    /// 过滤用户可访问的主机列表
    pub fn filter_hosts<'a>(
        allowed_hosts: &[String],
        all_hosts: &'a [HostEntry],
    ) -> Vec<&'a HostEntry> {
        if allowed_hosts.contains(&"*".to_string()) {
            return all_hosts.iter().collect();
        }

        all_hosts
            .iter()
            .filter(|h| allowed_hosts.contains(&h.name))
            .collect()
    }
}
