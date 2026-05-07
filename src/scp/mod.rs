/// SCP protocol parser and auditor
///
/// SCP protocol overview:
/// - Upload (scp -t): client sends files TO the server
///   Protocol: C<mode> <size> <filename>\n<data>\0
/// - Download (scp -f): client requests files FROM the server  
///   Protocol: server sends C<mode> <size> <filename>\n<data>\0
///
/// Directory handling:
/// - D<mode> <size> <dirname>\n  (enter directory)
/// - E\n                          (leave directory)

use tracing::info;

/// SCP transfer direction
#[derive(Debug, Clone, PartialEq)]
pub enum ScpDirection {
    /// Upload: client -> target (scp -t)
    Upload,
    /// Download: target -> client (scp -f)
    Download,
}

impl std::fmt::Display for ScpDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScpDirection::Upload => write!(f, "upload"),
            ScpDirection::Download => write!(f, "download"),
        }
    }
}

/// Parsed SCP command from exec_request
#[derive(Debug, Clone)]
pub struct ScpCommand {
    pub direction: ScpDirection,
    /// Target path on the remote host
    pub remote_path: String,
    /// Whether recursive mode is enabled (-r)
    pub recursive: bool,
    /// Whether preserve mode is enabled (-p)
    pub preserve: bool,
}

/// SCP file transfer info extracted from the protocol stream
#[derive(Debug, Clone)]
pub struct ScpFileInfo {
    /// File name
    pub filename: String,
    /// File size in bytes
    pub size: u64,
    /// File mode (permissions), e.g. "0644"
    pub mode: String,
    /// Transfer direction
    pub direction: ScpDirection,
}

/// State machine for parsing SCP data stream
#[derive(Debug, Clone)]
pub enum ScpParserState {
    /// Waiting for protocol header line (C/D/E line)
    WaitingHeader,
    /// Currently receiving file data
    ReceivingData {
        file_info: ScpFileInfo,
        bytes_received: u64,
    },
    /// Transfer complete for current file
    Done,
}

/// SCP protocol stream parser
pub struct ScpParser {
    pub direction: ScpDirection,
    pub remote_path: String,
    state: ScpParserState,
    /// Buffer for accumulating header lines
    header_buffer: Vec<u8>,
    /// All files transferred in this session
    pub files: Vec<ScpFileInfo>,
    /// Current directory path stack (for recursive transfers)
    dir_stack: Vec<String>,
}

impl ScpParser {
    pub fn new(command: &ScpCommand) -> Self {
        Self {
            direction: command.direction.clone(),
            remote_path: command.remote_path.clone(),
            state: ScpParserState::WaitingHeader,
            header_buffer: Vec::new(),
            files: Vec::new(),
            dir_stack: Vec::new(),
        }
    }

    /// Parse data flowing through the SCP stream.
    /// Returns any newly detected file transfers.
    pub fn parse_data(&mut self, data: &[u8]) -> Vec<ScpFileInfo> {
        let mut new_files = Vec::new();

        let mut offset = 0;
        while offset < data.len() {
            match &self.state {
                ScpParserState::WaitingHeader => {
                    // Look for newline to complete the header
                    if let Some(nl_pos) = data[offset..].iter().position(|&b| b == b'\n') {
                        self.header_buffer.extend_from_slice(&data[offset..offset + nl_pos]);
                        offset += nl_pos + 1;

                        // Parse the completed header line
                        let header = String::from_utf8_lossy(&self.header_buffer).to_string();
                        self.header_buffer.clear();

                        if let Some(file_info) = self.parse_header_line(&header) {
                            let size = file_info.size;
                            info!(
                                "SCP file detected: {} ({} bytes, mode {})",
                                file_info.filename, file_info.size, file_info.mode
                            );
                            new_files.push(file_info.clone());
                            self.files.push(file_info.clone());

                            if size == 0 {
                                self.state = ScpParserState::Done;
                            } else {
                                self.state = ScpParserState::ReceivingData {
                                    file_info,
                                    bytes_received: 0,
                                };
                            }
                        }
                    } else {
                        // No newline yet, buffer the data
                        self.header_buffer.extend_from_slice(&data[offset..]);
                        break;
                    }
                }
                ScpParserState::ReceivingData {
                    file_info,
                    bytes_received,
                } => {
                    let remaining = file_info.size - bytes_received;
                    let available = (data.len() - offset) as u64;

                    if available >= remaining {
                        // File data complete (+ 1 byte for trailing \0)
                        offset += remaining as usize;
                        // Skip the trailing \0 if present
                        if offset < data.len() && data[offset] == 0 {
                            offset += 1;
                        }
                        info!(
                            "SCP file transfer complete: {} ({} bytes)",
                            file_info.filename, file_info.size
                        );
                        self.state = ScpParserState::WaitingHeader;
                    } else {
                        // Still receiving data
                        let new_received = bytes_received + available;
                        let fi = file_info.clone();
                        self.state = ScpParserState::ReceivingData {
                            file_info: fi,
                            bytes_received: new_received,
                        };
                        break;
                    }
                }
                ScpParserState::Done => {
                    self.state = ScpParserState::WaitingHeader;
                }
            }
        }

        new_files
    }

    /// Parse a header line like "C0644 12345 filename.txt" or "D0755 0 dirname"
    fn parse_header_line(&mut self, line: &str) -> Option<ScpFileInfo> {
        let line = line.trim();

        if line.is_empty() {
            return None;
        }

        // Skip ACK bytes (0x00, 0x01, 0x02)
        let line = line.trim_start_matches(|c: char| c as u32 <= 2);

        match line.chars().next()? {
            'C' => {
                // Regular file: C<mode> <size> <filename>
                let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
                if parts.len() == 3 {
                    let mode = parts[0].to_string();
                    let size: u64 = parts[1].parse().ok()?;
                    let filename = parts[2].to_string();

                    let full_path = if self.dir_stack.is_empty() {
                        filename.clone()
                    } else {
                        format!("{}/{}", self.dir_stack.join("/"), filename)
                    };

                    Some(ScpFileInfo {
                        filename: full_path,
                        size,
                        mode,
                        direction: self.direction.clone(),
                    })
                } else {
                    None
                }
            }
            'D' => {
                // Directory entry: D<mode> <size> <dirname>
                let parts: Vec<&str> = line[1..].splitn(3, ' ').collect();
                if parts.len() == 3 {
                    let dirname = parts[2].to_string();
                    self.dir_stack.push(dirname);
                }
                None
            }
            'E' => {
                // Exit directory
                self.dir_stack.pop();
                None
            }
            _ => None,
        }
    }
}

/// Parse an SCP exec command string.
/// Examples:
///   "scp -t /tmp/file.txt"       -> Upload to /tmp/file.txt
///   "scp -f /home/user/data.csv" -> Download from /home/user/data.csv
///   "scp -r -t /tmp/dir"         -> Recursive upload
pub fn parse_scp_command(cmd: &str) -> Option<ScpCommand> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    if parts.is_empty() || parts[0] != "scp" {
        return None;
    }

    let mut direction = None;
    let mut recursive = false;
    let mut preserve = false;
    let mut remote_path = String::new();

    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "-t" => {
                direction = Some(ScpDirection::Upload);
                // Next arg is the path
                if i + 1 < parts.len() {
                    remote_path = parts[i + 1..].join(" ");
                    break;
                }
            }
            "-f" => {
                direction = Some(ScpDirection::Download);
                if i + 1 < parts.len() {
                    remote_path = parts[i + 1..].join(" ");
                    break;
                }
            }
            "-r" => recursive = true,
            "-p" => preserve = true,
            "-d" => {} // directory hint, ignore
            arg if arg.starts_with('-') => {} // other flags
            _ => {
                // Could be the path after -t/-f was already set
            }
        }
        i += 1;
    }

    direction.map(|dir| ScpCommand {
        direction: dir,
        remote_path,
        recursive,
        preserve,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scp_upload() {
        let cmd = parse_scp_command("scp -t /tmp/file.txt").unwrap();
        assert_eq!(cmd.direction, ScpDirection::Upload);
        assert_eq!(cmd.remote_path, "/tmp/file.txt");
        assert!(!cmd.recursive);
    }

    #[test]
    fn test_parse_scp_download() {
        let cmd = parse_scp_command("scp -f /home/user/data.csv").unwrap();
        assert_eq!(cmd.direction, ScpDirection::Download);
        assert_eq!(cmd.remote_path, "/home/user/data.csv");
    }

    #[test]
    fn test_parse_scp_recursive() {
        let cmd = parse_scp_command("scp -r -t /tmp/dir").unwrap();
        assert_eq!(cmd.direction, ScpDirection::Upload);
        assert_eq!(cmd.remote_path, "/tmp/dir");
        assert!(cmd.recursive);
    }

    #[test]
    fn test_parse_scp_preserve() {
        let cmd = parse_scp_command("scp -p -r -t /tmp/dir").unwrap();
        assert!(cmd.preserve);
        assert!(cmd.recursive);
    }

    #[test]
    fn test_parse_non_scp() {
        assert!(parse_scp_command("ls -la").is_none());
        assert!(parse_scp_command("rsync -avz").is_none());
    }

    #[test]
    fn test_parse_header_file() {
        let cmd = ScpCommand {
            direction: ScpDirection::Upload,
            remote_path: "/tmp".into(),
            recursive: false,
            preserve: false,
        };
        let mut parser = ScpParser::new(&cmd);
        let files = parser.parse_data(b"C0644 1234 test.txt\n");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "test.txt");
        assert_eq!(files[0].size, 1234);
        assert_eq!(files[0].mode, "0644");
    }

    #[test]
    fn test_parse_header_directory() {
        let cmd = ScpCommand {
            direction: ScpDirection::Upload,
            remote_path: "/tmp".into(),
            recursive: true,
            preserve: false,
        };
        let mut parser = ScpParser::new(&cmd);

        // Enter directory
        let files = parser.parse_data(b"D0755 0 mydir\n");
        assert_eq!(files.len(), 0);

        // File inside directory
        let files = parser.parse_data(b"C0644 100 inner.txt\n");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "mydir/inner.txt");

        // Exit directory
        let files = parser.parse_data(b"E\n");
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn test_parse_full_transfer() {
        let cmd = ScpCommand {
            direction: ScpDirection::Upload,
            remote_path: "/tmp".into(),
            recursive: false,
            preserve: false,
        };
        let mut parser = ScpParser::new(&cmd);

        // Header
        let files = parser.parse_data(b"C0644 5 hi.txt\n");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].size, 5);

        // Data + trailing null
        let files = parser.parse_data(b"hello\x00");
        assert_eq!(files.len(), 0);

        // Next file
        let files = parser.parse_data(b"C0644 3 b.txt\n");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "b.txt");
    }
}
