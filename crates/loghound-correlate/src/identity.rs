//! Canonical identity-key construction per entity kind (`PLAN.md` §2).
//!
//! The keys chosen here are what make dedup and PID-reuse handling correct:
//! a [`process_key`] embeds the launch time so a reused PID becomes a distinct
//! process node, while a [`user_key`] prefers the stable SID.

/// Canonicalize a hostname (case-insensitive; trims). FQDN or NetBIOS as given.
pub fn host_key(host: &str) -> String {
    host.trim().to_lowercase()
}

/// User identity: SID when present (stable across renames), else `domain\name`,
/// else bare `name`. Treats `-` and empty as absent.
pub fn user_key(name: &str, domain: Option<&str>, sid: Option<&str>) -> String {
    if let Some(s) = sid {
        let s = s.trim();
        if !s.is_empty() && s != "-" {
            return s.to_lowercase();
        }
    }
    let name = name.trim().to_lowercase();
    match domain {
        Some(d) if !d.trim().is_empty() && d.trim() != "-" => {
            format!("{}\\{}", d.trim().to_lowercase(), name)
        }
        _ => name,
    }
}

/// Process *instance* identity: `host:pid:start_ms`. Embedding the start time is
/// what disambiguates PID reuse (`PLAN.md` §2, §8).
pub fn process_key(host: &str, pid: i64, start_ms: i64) -> String {
    format!("{}:{}:{}", host_key(host), pid, start_ms)
}

/// Executable (binary on disk) identity: normalized image path, else name.
pub fn executable_key(path_or_name: &str) -> String {
    path_or_name.trim().to_lowercase()
}

/// Logon session identity: `host:logon_id`.
pub fn session_key(host: &str, logon_id: &str) -> String {
    format!("{}:{}", host_key(host), logon_id.trim())
}

/// File identity: `host:normalized_path`.
pub fn file_key(host: &str, path: &str) -> String {
    format!("{}:{}", host_key(host), path.trim().to_lowercase())
}

/// The trailing path component (handles both `\\` and `/` separators).
pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_key_prefers_sid() {
        assert_eq!(
            user_key("alice", Some("CORP"), Some("S-1-5-21-1")),
            "s-1-5-21-1"
        );
        assert_eq!(user_key("Alice", Some("CORP"), None), "corp\\alice");
        assert_eq!(user_key("alice", None, Some("-")), "alice");
        assert_eq!(user_key("alice", Some("-"), None), "alice");
    }

    #[test]
    fn process_key_distinguishes_pid_reuse() {
        // Same host+pid, different start => different identity.
        assert_ne!(process_key("H", 200, 1000), process_key("H", 200, 5000));
    }

    #[test]
    fn basename_handles_windows_and_unix() {
        assert_eq!(basename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe");
        assert_eq!(basename("/usr/bin/bash"), "bash");
        assert_eq!(basename("plain.exe"), "plain.exe");
    }
}
