use tracing::warn;

use crate::config::UserEntry;

/// Command filter action result
#[derive(Debug, Clone, PartialEq)]
pub enum FilterAction {
    /// Command is allowed to pass through
    Allow,
    /// Command is blocked with a reason
    Block(String),
}

/// Command filter that checks user input against blacklist/whitelist rules
pub struct CommandFilter {
    mode: FilterMode,
    /// Blocked command patterns (substring match) for blacklist mode
    blocked_patterns: Vec<String>,
    /// Allowed command prefixes for whitelist mode
    allowed_prefixes: Vec<String>,
    /// Username for logging
    username: String,
}

#[derive(Debug, Clone, PartialEq)]
enum FilterMode {
    None,
    Blacklist,
    Whitelist,
}

impl CommandFilter {
    /// Create a new command filter from user configuration
    pub fn from_user_config(user: &UserEntry) -> Self {
        let mode = match user.command_filter_mode.as_str() {
            "blacklist" => FilterMode::Blacklist,
            "whitelist" => FilterMode::Whitelist,
            _ => FilterMode::None,
        };

        Self {
            mode,
            blocked_patterns: user.blocked_commands.clone(),
            allowed_prefixes: user.allowed_commands.clone(),
            username: user.name.clone(),
        }
    }

    /// Check if a command line is allowed
    pub fn check_command(&self, command_line: &str) -> FilterAction {
        match self.mode {
            FilterMode::None => FilterAction::Allow,
            FilterMode::Blacklist => self.check_blacklist(command_line),
            FilterMode::Whitelist => self.check_whitelist(command_line),
        }
    }

    /// Returns true if filtering is enabled for this user
    pub fn is_enabled(&self) -> bool {
        self.mode != FilterMode::None
    }

    /// Blacklist mode: block if any pattern matches (substring)
    fn check_blacklist(&self, command_line: &str) -> FilterAction {
        // Split by command separators to check each sub-command
        let commands = split_commands(command_line);

        for cmd in &commands {
            let cmd_trimmed = cmd.trim();
            for pattern in &self.blocked_patterns {
                if cmd_trimmed.contains(pattern.as_str()) {
                    warn!(
                        "BLOCKED command for user '{}': '{}' (matched pattern: '{}')",
                        self.username, cmd_trimmed, pattern
                    );
                    return FilterAction::Block(format!(
                        "Command blocked: '{}' matches blacklisted pattern '{}'",
                        cmd_trimmed, pattern
                    ));
                }
            }
        }

        FilterAction::Allow
    }

    /// Whitelist mode: allow only if command name matches an allowed prefix
    fn check_whitelist(&self, command_line: &str) -> FilterAction {
        let commands = split_commands(command_line);

        for cmd in &commands {
            let cmd_trimmed = cmd.trim();
            if cmd_trimmed.is_empty() {
                continue;
            }

            // Extract the command name (first word)
            let cmd_name = cmd_trimmed
                .split_whitespace()
                .next()
                .unwrap_or("");

            // Check against allowed list
            let is_allowed = self.allowed_prefixes.iter().any(|allowed| {
                // Match exact command name or command starts with allowed prefix
                cmd_name == allowed.as_str()
                    || cmd_name.ends_with(&format!("/{}", allowed))
            });

            if !is_allowed {
                warn!(
                    "BLOCKED command for user '{}': '{}' (not in whitelist)",
                    self.username, cmd_trimmed
                );
                return FilterAction::Block(format!(
                    "Command blocked: '{}' is not in the allowed command list",
                    cmd_name
                ));
            }
        }

        FilterAction::Allow
    }
}

/// Split a command line by shell separators (;, &&, ||, |)
/// This handles basic cases - not a full shell parser
fn split_commands(input: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = '\0';

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double_quote && prev_char != '\\' => {
                in_single_quote = !in_single_quote;
                current.push(ch);
            }
            '"' if !in_single_quote && prev_char != '\\' => {
                in_double_quote = !in_double_quote;
                current.push(ch);
            }
            ';' if !in_single_quote && !in_double_quote => {
                commands.push(current.clone());
                current.clear();
            }
            '&' if !in_single_quote && !in_double_quote => {
                if chars.peek() == Some(&'&') {
                    chars.next(); // consume second '&'
                    commands.push(current.clone());
                    current.clear();
                } else {
                    // Background operator - still part of current command
                    current.push(ch);
                }
            }
            '|' if !in_single_quote && !in_double_quote => {
                if chars.peek() == Some(&'|') {
                    chars.next(); // consume second '|'
                    commands.push(current.clone());
                    current.clear();
                } else {
                    // Pipe: the next part is also a command
                    commands.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
        prev_char = ch;
    }

    if !current.trim().is_empty() {
        commands.push(current);
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_commands_simple() {
        let cmds = split_commands("ls -la");
        assert_eq!(cmds, vec!["ls -la"]);
    }

    #[test]
    fn test_split_commands_semicolon() {
        let cmds = split_commands("cd /tmp; rm -rf *");
        assert_eq!(cmds, vec!["cd /tmp", " rm -rf *"]);
    }

    #[test]
    fn test_split_commands_and() {
        let cmds = split_commands("make && make install");
        assert_eq!(cmds, vec!["make ", " make install"]);
    }

    #[test]
    fn test_split_commands_pipe() {
        let cmds = split_commands("ps aux | grep ssh");
        assert_eq!(cmds, vec!["ps aux ", " grep ssh"]);
    }

    #[test]
    fn test_split_commands_quoted() {
        let cmds = split_commands("echo 'hello; world' && ls");
        assert_eq!(cmds, vec!["echo 'hello; world' ", " ls"]);
    }

    #[test]
    fn test_blacklist_blocks() {
        let user = UserEntry {
            name: "test".into(),
            password_hash: "".into(),
            public_keys: vec![],
            allowed_hosts: vec![],
            command_filter_mode: "blacklist".into(),
            blocked_commands: vec!["rm -rf".into(), "shutdown".into(), "reboot".into()],
            allowed_commands: vec![],
            can_watch_sessions: false,
            watch_allowed_users: vec![],
        };

        let filter = CommandFilter::from_user_config(&user);
        assert_eq!(filter.check_command("ls -la"), FilterAction::Allow);
        assert!(matches!(filter.check_command("rm -rf /"), FilterAction::Block(_)));
        assert!(matches!(filter.check_command("sudo shutdown -h now"), FilterAction::Block(_)));
        assert_eq!(filter.check_command("cat file.txt"), FilterAction::Allow);
    }

    #[test]
    fn test_whitelist_allows() {
        let user = UserEntry {
            name: "test".into(),
            password_hash: "".into(),
            public_keys: vec![],
            allowed_hosts: vec![],
            command_filter_mode: "whitelist".into(),
            blocked_commands: vec![],
            allowed_commands: vec!["ls".into(), "cat".into(), "grep".into(), "ps".into()],
            can_watch_sessions: false,
            watch_allowed_users: vec![],
        };

        let filter = CommandFilter::from_user_config(&user);
        assert_eq!(filter.check_command("ls -la"), FilterAction::Allow);
        assert_eq!(filter.check_command("cat /etc/passwd"), FilterAction::Allow);
        assert!(matches!(filter.check_command("rm file.txt"), FilterAction::Block(_)));
        assert!(matches!(filter.check_command("shutdown -h now"), FilterAction::Block(_)));
    }

    #[test]
    fn test_blacklist_with_chained_commands() {
        let user = UserEntry {
            name: "test".into(),
            password_hash: "".into(),
            public_keys: vec![],
            allowed_hosts: vec![],
            command_filter_mode: "blacklist".into(),
            blocked_commands: vec!["rm -rf".into()],
            allowed_commands: vec![],
            can_watch_sessions: false,
            watch_allowed_users: vec![],
        };

        let filter = CommandFilter::from_user_config(&user);
        assert!(matches!(
            filter.check_command("ls && rm -rf /"),
            FilterAction::Block(_)
        ));
    }

    #[test]
    fn test_none_mode_allows_everything() {
        let user = UserEntry {
            name: "test".into(),
            password_hash: "".into(),
            public_keys: vec![],
            allowed_hosts: vec![],
            command_filter_mode: "none".into(),
            blocked_commands: vec![],
            allowed_commands: vec![],
            can_watch_sessions: false,
            watch_allowed_users: vec![],
        };

        let filter = CommandFilter::from_user_config(&user);
        assert_eq!(filter.check_command("rm -rf /"), FilterAction::Allow);
    }
}
