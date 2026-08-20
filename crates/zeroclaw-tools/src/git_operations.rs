use crate::helpers::domain_guard;
use async_trait::async_trait;
use reqwest::Url;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::autonomy::AutonomyLevel;
use zeroclaw_config::policy::SecurityPolicy;

/// Default timeout for network-backed git operations (clone, pull, fetch).
const NETWORK_GIT_TIMEOUT_SECS: u64 = 120;

const TOOL_DESCRIPTION_KEY: &str = "tool-git-operations";
static TOOL_DESCRIPTION: OnceLock<String> = OnceLock::new();

/// Git operations tool for structured repository management.
/// Provides safe, parsed git operations with JSON output.
pub struct GitOperationsTool {
    security: Arc<SecurityPolicy>,
    workspace_dir: std::path::PathBuf,
}

impl GitOperationsTool {
    pub fn new(security: Arc<SecurityPolicy>, workspace_dir: std::path::PathBuf) -> Self {
        Self {
            security,
            workspace_dir,
        }
    }

    /// Sanitize git arguments to prevent injection attacks
    fn sanitize_git_args(&self, args: &str) -> anyhow::Result<Vec<String>> {
        let mut result = Vec::new();
        for arg in args.split_whitespace() {
            // Block dangerous git options that could lead to command injection
            let arg_lower = arg.to_lowercase();
            if arg_lower.starts_with("--exec=")
                || arg_lower.starts_with("--upload-pack=")
                || arg_lower.starts_with("--receive-pack=")
                || arg_lower.starts_with("--pager=")
                || arg_lower.starts_with("--editor=")
                || arg_lower == "--no-verify"
                || arg_lower.contains("$(")
                || arg_lower.contains('`')
                || arg.contains('|')
                || arg.contains(';')
                || arg.contains('>')
            {
                anyhow::bail!("Blocked potentially dangerous git argument: {arg}");
            }
            // Block `-c` config injection (exact match or `-c=...` prefix).
            // This must not false-positive on `--cached` or `-cached`.
            if arg_lower == "-c" || arg_lower.starts_with("-c=") {
                anyhow::bail!("Blocked potentially dangerous git argument: {arg}");
            }
            result.push(arg.to_string());
        }
        Ok(result)
    }

    /// Check if an operation requires write access
    fn requires_write_access(&self, operation: &str) -> bool {
        matches!(
            operation,
            "commit"
                | "add"
                | "checkout"
                | "stash"
                | "reset"
                | "revert"
                | "worktree"
                | "clone"
                | "pull"
        )
    }

    #[cfg(test)]
    fn is_read_only(&self, operation: &str) -> bool {
        matches!(
            operation,
            "status" | "diff" | "log" | "show" | "branch" | "rev-parse" | "fetch"
        )
    }

    /// Resolve a user-provided path to an absolute path within the workspace.
    /// Returns the workspace_dir if no path is provided.
    /// Rejects paths that escape the workspace via traversal.
    fn resolve_working_dir(&self, path: Option<&str>) -> anyhow::Result<std::path::PathBuf> {
        let base = match path {
            Some(p) if !p.is_empty() => {
                let candidate = if std::path::Path::new(p).is_absolute() {
                    std::path::PathBuf::from(p)
                } else {
                    self.workspace_dir.join(p)
                };
                let resolved = candidate.canonicalize().map_err(|e| {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "path": p,
                                "error": format!("{}", e),
                            })),
                        "git_operations: cannot resolve path"
                    );
                    anyhow::Error::msg(format!("Cannot resolve path '{}': {}", p, e))
                })?;
                let workspace_canonical = self
                    .workspace_dir
                    .canonicalize()
                    .unwrap_or_else(|_| self.workspace_dir.clone());
                if !resolved.starts_with(&workspace_canonical) {
                    anyhow::bail!("Path '{}' resolves outside the workspace directory", p);
                }
                resolved
            }
            _ => self.workspace_dir.clone(),
        };
        Ok(base)
    }

    fn candidate_path(&self, raw_path: &str) -> anyhow::Result<PathBuf> {
        if raw_path.contains('\0') {
            anyhow::bail!("Path not allowed: contains null byte");
        }
        if Path::new(raw_path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!("Path not allowed: parent-directory traversal is not allowed");
        }

        let raw = Path::new(raw_path);
        Ok(if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            self.workspace_dir.join(raw)
        })
    }

    /// Validate a git remote name against a strict allowlist. Rejects option
    /// injection (`--all`, `--delete`) and shell metacharacters.
    fn validate_remote_name<'a>(&self, remote: &'a str) -> anyhow::Result<&'a str> {
        if remote.is_empty() {
            anyhow::bail!("remote name cannot be empty");
        }
        let mut chars = remote.chars();
        let first = chars.next().unwrap();
        if !(first.is_ascii_alphanumeric() || first == '_') {
            anyhow::bail!(
                "remote name '{}' must start with a letter, digit, or '_'",
                remote
            );
        }
        if !remote
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            anyhow::bail!("remote name '{}' contains invalid characters", remote);
        }
        Ok(remote)
    }

    /// Validate a branch, revision, or commit-ish value. Rejects leading `-`
    /// (git option injection, e.g. `git diff --output=...`), whitespace, and
    /// control characters.
    fn validate_revision<'a>(&self, rev: &'a str) -> anyhow::Result<&'a str> {
        if rev.is_empty() {
            anyhow::bail!("revision cannot be empty");
        }
        if rev.starts_with('-') {
            anyhow::bail!("revision '{}' must not start with '-'", rev);
        }
        if rev.chars().any(char::is_whitespace)
            || rev.chars().any(|c| c.is_control())
            || rev.contains('|')
            || rev.contains(';')
            || rev.contains('`')
        {
            anyhow::bail!("revision '{}' contains invalid characters", rev);
        }
        Ok(rev)
    }

    /// Validate a clone destination directory name. Single path component only;
    /// rejects traversal, absolute paths, hidden/`~`/`-` prefixes, and
    /// separators so the resolved target cannot escape the workspace.
    fn validate_destination_component<'a>(&self, dest: &'a str) -> anyhow::Result<&'a str> {
        if dest.is_empty() {
            anyhow::bail!("destination cannot be empty");
        }
        if dest == "." || dest == ".." {
            anyhow::bail!("destination cannot be '.' or '..'");
        }
        if dest.starts_with('.') || dest.starts_with('~') || dest.starts_with('-') {
            anyhow::bail!(
                "destination cannot start with '.', '~', or '-' (got '{}')",
                dest
            );
        }
        if dest.contains(['/', '\\', '\0']) || dest.chars().any(char::is_whitespace) {
            anyhow::bail!("destination '{}' must be a single directory name", dest);
        }
        Ok(dest)
    }

    /// Validate a clone URL: https-only, no embedded credentials, and the host
    /// must be globally routable (SSRF guard). Returns the normalized URL.
    fn validate_clone_url(&self, url: &str) -> anyhow::Result<String> {
        let url = url.trim();
        if url.is_empty() {
            anyhow::bail!("clone URL cannot be empty");
        }
        if url.chars().any(char::is_whitespace) {
            anyhow::bail!("clone URL cannot contain whitespace");
        }
        let parsed = Url::parse(url).map_err(|_| anyhow::anyhow!("invalid clone URL"))?;
        if parsed.scheme() != "https" {
            anyhow::bail!("only https:// clone URLs are allowed");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            anyhow::bail!("clone URL must not contain embedded credentials");
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("clone URL must include a host"))?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>()
            && domain_guard::is_cloud_metadata_ip(ip)
        {
            anyhow::bail!("blocked cloud metadata clone host: {host}");
        }
        if domain_guard::is_private_or_local_host(host) {
            anyhow::bail!("blocked local/private clone host: {host}");
        }
        Ok(parsed.to_string())
    }

    /// Derive a safe destination directory name from a validated clone URL's
    /// final path segment (stripping a trailing `.git`).
    fn extract_destination_from_url(url: &str) -> String {
        let parsed = Url::parse(url).expect("clone URL was already validated");
        let last = parsed
            .path()
            .split('/')
            .filter(|s| !s.is_empty())
            .next_back()
            .unwrap_or("");
        let name = last.trim_end_matches(".git");
        if name.is_empty() || name == "." || name == ".." {
            "repo".to_string()
        } else {
            name.to_string()
        }
    }

    /// Resolve the clone target directory. `parent` (the 'path' parameter) is
    /// the existing parent directory the clone is created under; `destination`
    /// is a validated single directory component. The target must not exist.
    fn resolve_clone_target(
        &self,
        parent: Option<&str>,
        destination: &str,
    ) -> anyhow::Result<PathBuf> {
        let base = self.resolve_working_dir(parent)?;
        let target = base.join(destination);
        if target.exists() {
            anyhow::bail!("destination already exists: {}", target.display());
        }
        Ok(target)
    }

    /// Run a network-backed git operation with a scrubbed environment.
    ///
    /// Clears the process environment and re-adds only what is needed so the
    /// user's ambient git configuration and credentials cannot reach the remote
    /// (mirrors the shell tool's CWE-200 env hygiene): no credential helpers,
    /// no `GIT_ASKPASS`, no `url.*.insteadOf` rewrites, no smudge/clean filter
    /// commands from global config. System/global gitconfig is disabled and
    /// `safe.directory` is set explicitly for the working directory. A timeout
    /// bounds hung or malicious servers.
    async fn run_network_git_command(
        &self,
        args: &[&str],
        working_dir: &std::path::Path,
    ) -> anyhow::Result<String> {
        let mut cmd = tokio::process::Command::new("git");
        cmd.current_dir(working_dir)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("TMPDIR", std::env::var("TMPDIR").unwrap_or_default())
            .env("TEMP", std::env::var("TEMP").unwrap_or_default())
            .env("TMP", std::env::var("TMP").unwrap_or_default())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(std::process::Stdio::null());
        // `-c safe.directory=...` must precede the subcommand so a workspace
        // repo owned by another UID still works without the user's global config.
        cmd.arg("-c")
            .arg(format!("safe.directory={}", working_dir.display()))
            .args(args);
        // Proxy variables are operator-controlled (not model- or remote-
        // controlled) and required for corporate networks, so keep them.
        for proxy in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
            "no_proxy",
            "NO_PROXY",
        ] {
            if let Ok(value) = std::env::var(proxy) {
                cmd.env(proxy, value);
            }
        }

        let output =
            tokio::time::timeout(Duration::from_secs(NETWORK_GIT_TIMEOUT_SECS), cmd.output())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "git network operation timed out after {NETWORK_GIT_TIMEOUT_SECS} seconds"
                    )
                })??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Git command failed: {stderr}");
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn result_success(message: String) -> ToolResult {
        ToolResult {
            success: true,
            output: message.into(),
            error: None,
        }
    }

    fn result_failure(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: ToolOutput::default(),
            error: Some(message),
        }
    }

    /// Localized tool error text (fixed key).
    fn ferr(key: &str) -> String {
        crate::i18n::get_required_tool_string(key)
    }

    /// Localized tool error text with Fluent `{ $name }` interpolation.
    fn ferr_args(key: &str, args: &[(&str, &str)]) -> String {
        crate::i18n::get_required_tool_string_with_args(key, args)
    }

    fn ensure_worktree_add_target_allowed(&self, raw_path: &str) -> anyhow::Result<PathBuf> {
        let candidate = self.candidate_path(raw_path)?;
        let parent = candidate.parent().ok_or_else(|| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"raw_path": raw_path})),
                "git_operations: worktree path has no parent"
            );
            anyhow::Error::msg("Worktree path must have a parent directory")
        })?;
        let file_name = candidate.file_name().ok_or_else(|| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"raw_path": raw_path})),
                "git_operations: worktree path has no file name"
            );
            anyhow::Error::msg("Worktree path must include a final path component")
        })?;
        let resolved_parent = parent.canonicalize().map_err(|e| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "parent": parent.display().to_string(),
                        "error": format!("{}", e),
                    })),
                "git_operations: cannot resolve worktree parent"
            );
            anyhow::Error::msg(format!(
                "Cannot resolve worktree parent '{}': {e}",
                parent.display()
            ))
        })?;
        let resolved_target = resolved_parent.join(file_name);

        if !self.security.is_resolved_path_allowed(&resolved_target) {
            anyhow::bail!(
                "Worktree path '{}' resolves outside the workspace or allowed roots",
                raw_path
            );
        }

        Ok(resolved_target)
    }

    fn ensure_worktree_remove_target_allowed(&self, raw_path: &str) -> anyhow::Result<PathBuf> {
        let candidate = self.candidate_path(raw_path)?;
        let resolved = candidate.canonicalize().map_err(|e| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "raw_path": raw_path,
                        "error": format!("{}", e),
                    })),
                "git_operations: cannot resolve worktree path"
            );
            anyhow::Error::msg(format!("Cannot resolve worktree path '{}': {e}", raw_path))
        })?;

        if !self.security.is_resolved_path_allowed(&resolved) {
            anyhow::bail!(
                "Worktree path '{}' resolves outside the workspace or allowed roots",
                raw_path
            );
        }

        Ok(resolved)
    }

    async fn run_git_command(
        &self,
        args: &[&str],
        working_dir: &std::path::Path,
    ) -> anyhow::Result<String> {
        let output = tokio::process::Command::new("git")
            .args(args)
            .current_dir(working_dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(std::process::Stdio::null())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Git command failed: {stderr}");
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn git_status(
        &self,
        _args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let output = self
            .run_git_command(&["status", "--porcelain=2", "--branch"], working_dir)
            .await?;

        // Parse git status output into structured format
        let mut result = serde_json::Map::new();
        let mut branch = String::new();
        let mut staged = Vec::new();
        let mut unstaged = Vec::new();
        let mut untracked = Vec::new();

        for line in output.lines() {
            if line.starts_with("# branch.head ") {
                branch = line.trim_start_matches("# branch.head ").to_string();
            } else if let Some(rest) = line.strip_prefix("1 ") {
                // Ordinary changed entry
                let mut parts = rest.splitn(3, ' ');
                if let (Some(staging), Some(path)) = (parts.next(), parts.next())
                    && !staging.is_empty()
                {
                    let status_char = staging.chars().next().unwrap_or(' ');
                    if status_char != '.' && status_char != ' ' {
                        staged.push(json!({"path": path, "status": status_char}));
                    }
                    let status_char = staging.chars().nth(1).unwrap_or(' ');
                    if status_char != '.' && status_char != ' ' {
                        unstaged.push(json!({"path": path, "status": status_char}));
                    }
                }
            } else if let Some(rest) = line.strip_prefix("? ") {
                untracked.push(rest.to_string());
            }
        }

        result.insert("branch".to_string(), json!(branch));
        result.insert("staged".to_string(), json!(staged));
        result.insert("unstaged".to_string(), json!(unstaged));
        result.insert("untracked".to_string(), json!(untracked));
        result.insert(
            "clean".to_string(),
            json!(staged.is_empty() && unstaged.is_empty() && untracked.is_empty()),
        );

        Ok(ToolResult {
            success: true,
            output: serde_json::to_string_pretty(&result)
                .unwrap_or_default()
                .into(),
            error: None,
        })
    }

    async fn git_diff(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let files = args.get("files").and_then(|v| v.as_str()).unwrap_or(".");
        let cached = args
            .get("cached")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Validate files argument against injection patterns
        self.sanitize_git_args(files)?;

        let mut git_args = vec!["diff", "--unified=3"];
        if cached {
            git_args.push("--cached");
        }
        if let Some(commit) = args.get("commit").and_then(|v| v.as_str())
            && !commit.is_empty()
        {
            git_args.push(self.validate_revision(commit)?);
        }
        git_args.push("--");
        git_args.push(files);

        let output = self.run_git_command(&git_args, working_dir).await?;

        // Parse diff into structured hunks
        let mut result = serde_json::Map::new();
        let mut hunks = Vec::new();
        let mut current_file = String::new();
        let mut current_hunk = serde_json::Map::new();
        let mut lines = Vec::new();

        for line in output.lines() {
            if line.starts_with("diff --git ") {
                if !lines.is_empty() {
                    current_hunk.insert("lines".to_string(), json!(lines));
                    if !current_hunk.is_empty() {
                        hunks.push(serde_json::Value::Object(current_hunk.clone()));
                    }
                    lines = Vec::new();
                    current_hunk = serde_json::Map::new();
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    current_file = parts[3].trim_start_matches("b/").to_string();
                    current_hunk.insert("file".to_string(), json!(current_file));
                }
            } else if line.starts_with("@@ ") {
                if !lines.is_empty() {
                    current_hunk.insert("lines".to_string(), json!(lines));
                    if !current_hunk.is_empty() {
                        hunks.push(serde_json::Value::Object(current_hunk.clone()));
                    }
                    lines = Vec::new();
                    current_hunk = serde_json::Map::new();
                    current_hunk.insert("file".to_string(), json!(current_file));
                }
                current_hunk.insert("header".to_string(), json!(line));
            } else if !line.is_empty() {
                lines.push(json!({
                    "text": line,
                    "type": if line.starts_with('+') { "add" }
                           else if line.starts_with('-') { "delete" }
                           else { "context" }
                }));
            }
        }

        if !lines.is_empty() {
            current_hunk.insert("lines".to_string(), json!(lines));
            if !current_hunk.is_empty() {
                hunks.push(serde_json::Value::Object(current_hunk));
            }
        }

        result.insert("hunks".to_string(), json!(hunks));
        result.insert("file_count".to_string(), json!(hunks.len()));

        Ok(ToolResult {
            success: true,
            output: serde_json::to_string_pretty(&result)
                .unwrap_or_default()
                .into(),
            error: None,
        })
    }

    async fn git_log(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let limit_raw = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10);
        let limit = usize::try_from(limit_raw).unwrap_or(usize::MAX).min(1000);
        let limit_str = limit.to_string();

        let output = self
            .run_git_command(
                &[
                    "log",
                    &format!("-{limit_str}"),
                    "--pretty=format:%H|%an|%ae|%ad|%s",
                    "--date=iso",
                ],
                working_dir,
            )
            .await?;

        let mut commits = Vec::new();

        for line in output.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 5 {
                commits.push(json!({
                    "hash": parts[0],
                    "author": parts[1],
                    "email": parts[2],
                    "date": parts[3],
                    "message": parts[4]
                }));
            }
        }

        Ok(ToolResult {
            success: true,
            output: serde_json::to_string_pretty(&json!({ "commits": commits }))
                .unwrap_or_default()
                .into(),
            error: None,
        })
    }

    async fn git_clone(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let url = match args.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                return Ok(Self::result_failure(Self::ferr(
                    "tool-git-operations-error-clone-missing-url",
                )));
            }
        };

        let validated_url = match self.validate_clone_url(url) {
            Ok(u) => u,
            Err(e) => {
                return Ok(Self::result_failure(Self::ferr_args(
                    "tool-git-operations-error-clone-url",
                    &[("reason", &format!("{e}"))],
                )));
            }
        };

        let destination = match args.get("destination").and_then(|v| v.as_str()) {
            Some(d) => match self.validate_destination_component(d) {
                Ok(d) => d.to_string(),
                Err(e) => {
                    return Ok(Self::result_failure(Self::ferr_args(
                        "tool-git-operations-error-clone-destination",
                        &[("reason", &format!("{e}"))],
                    )));
                }
            },
            None => Self::extract_destination_from_url(&validated_url),
        };

        let target = match self
            .resolve_clone_target(args.get("path").and_then(|v| v.as_str()), &destination)
        {
            Ok(t) => t,
            Err(e) => {
                return Ok(Self::result_failure(Self::ferr_args(
                    "tool-git-operations-error-clone-destination",
                    &[("reason", &format!("{e}"))],
                )));
            }
        };
        let target_str = match target.to_str() {
            Some(s) => s,
            None => {
                return Ok(Self::result_failure(Self::ferr_args(
                    "tool-git-operations-error-clone-destination",
                    &[("reason", "path is not valid UTF-8")],
                )));
            }
        };

        let mut git_args: Vec<String> = vec!["clone".into()];
        if let Some(depth) = args.get("depth").and_then(|v| v.as_u64()) {
            if depth == 0 {
                return Ok(Self::result_failure(Self::ferr(
                    "tool-git-operations-error-clone-depth",
                )));
            }
            git_args.push("--depth".into());
            git_args.push(depth.to_string());
        }
        git_args.push(validated_url.clone());
        git_args.push(target_str.to_string());

        let git_args_refs: Vec<&str> = git_args.iter().map(String::as_str).collect();
        match self
            .run_network_git_command(&git_args_refs, working_dir)
            .await
        {
            Ok(_) => Ok(Self::result_success(format!(
                "Cloned {} to {}",
                validated_url,
                target.display()
            ))),
            Err(e) => Ok(Self::result_failure(Self::ferr_args(
                "tool-git-operations-error-clone-failed",
                &[("error", &format!("{e}"))],
            ))),
        }
    }

    async fn git_pull(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let rebase = args
            .get("rebase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut git_args: Vec<String> = vec!["pull".into()];
        if rebase {
            git_args.push("--rebase".into());
        }

        if let Some(remote) = args.get("remote").and_then(|v| v.as_str()) {
            match self.validate_remote_name(remote) {
                Ok(remote) => git_args.push(remote.to_string()),
                Err(e) => {
                    return Ok(Self::result_failure(Self::ferr_args(
                        "tool-git-operations-error-invalid-remote",
                        &[("reason", &format!("{e}"))],
                    )));
                }
            }
        }
        if let Some(branch) = args.get("branch").and_then(|v| v.as_str()) {
            match self.validate_revision(branch) {
                Ok(branch) => git_args.push(branch.to_string()),
                Err(e) => {
                    return Ok(Self::result_failure(Self::ferr_args(
                        "tool-git-operations-error-invalid-branch",
                        &[("reason", &format!("{e}"))],
                    )));
                }
            }
        }

        let git_args_refs: Vec<&str> = git_args.iter().map(String::as_str).collect();
        match self
            .run_network_git_command(&git_args_refs, working_dir)
            .await
        {
            Ok(output) => Ok(Self::result_success(output)),
            Err(e) => Ok(Self::result_failure(Self::ferr_args(
                "tool-git-operations-error-pull-failed",
                &[("error", &format!("{e}"))],
            ))),
        }
    }

    async fn git_fetch(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let all = args.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
        let remote = args.get("remote").and_then(|v| v.as_str());

        let mut git_args: Vec<String> = vec!["fetch".into()];
        if all {
            if remote.is_some() {
                return Ok(Self::result_failure(Self::ferr(
                    "tool-git-operations-error-fetch-combine",
                )));
            }
            git_args.push("--all".into());
        } else {
            let remote = remote.unwrap_or("origin");
            match self.validate_remote_name(remote) {
                Ok(remote) => git_args.push(remote.to_string()),
                Err(e) => {
                    return Ok(Self::result_failure(Self::ferr_args(
                        "tool-git-operations-error-invalid-remote",
                        &[("reason", &format!("{e}"))],
                    )));
                }
            }
        }

        let git_args_refs: Vec<&str> = git_args.iter().map(String::as_str).collect();
        match self
            .run_network_git_command(&git_args_refs, working_dir)
            .await
        {
            Ok(output) => Ok(Self::result_success(output)),
            Err(e) => Ok(Self::result_failure(Self::ferr_args(
                "tool-git-operations-error-fetch-failed",
                &[("error", &format!("{e}"))],
            ))),
        }
    }

    async fn git_branch(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let remote_branches = args
            .get("remote_branches")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let output = if remote_branches {
            self.run_network_git_command(
                &["branch", "-r", "--format=%(refname:short)"],
                working_dir,
            )
            .await?
        } else {
            self.run_git_command(
                &["branch", "--format=%(refname:short)|%(HEAD)"],
                working_dir,
            )
            .await?
        };

        let mut branches = Vec::new();
        let mut current = String::new();

        for line in output.lines() {
            if remote_branches {
                if line.contains(" -> ") || line.trim().is_empty() {
                    continue;
                }
                branches.push(json!({
                    "name": line,
                    "current": false
                }));
            } else if let Some((name, head)) = line.split_once('|') {
                let is_current = head == "*";
                if is_current {
                    current = name.to_string();
                }
                branches.push(json!({
                    "name": name,
                    "current": is_current
                }));
            }
        }

        Ok(ToolResult {
            success: true,
            output: serde_json::to_string_pretty(&json!({
                "current": current,
                "branches": branches
            }))
            .unwrap_or_default()
            .into(),
            error: None,
        })
    }

    fn truncate_commit_message(message: &str) -> String {
        if message.chars().count() > 2000 {
            format!("{}...", message.chars().take(1997).collect::<String>())
        } else {
            message.to_string()
        }
    }

    async fn git_commit(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let message = args
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({"param": "message"})),
                    "git_operations: missing message parameter"
                );
                anyhow::Error::msg("Missing 'message' parameter")
            })?;

        let trimmed_lines: Vec<&str> = message.lines().map(|l| l.trim_end()).collect();
        // Drop leading blank lines.
        let trimmed_lines = trimmed_lines
            .iter()
            .copied()
            .skip_while(|l| l.is_empty())
            .collect::<Vec<_>>();
        // Collapse runs of more than 2 consecutive blank lines to 2.
        let mut sanitized_lines: Vec<&str> = Vec::with_capacity(trimmed_lines.len());
        let mut consecutive_blanks = 0usize;
        for line in &trimmed_lines {
            if line.is_empty() {
                consecutive_blanks += 1;
                if consecutive_blanks <= 2 {
                    sanitized_lines.push(line);
                }
            } else {
                consecutive_blanks = 0;
                sanitized_lines.push(line);
            }
        }
        // Drop trailing blank lines.
        while sanitized_lines.last().is_some_and(|l: &&str| l.is_empty()) {
            sanitized_lines.pop();
        }
        let sanitized = sanitized_lines.join("\n");

        if sanitized.is_empty() {
            anyhow::bail!("Commit message cannot be empty");
        }

        // Limit message length
        let message = Self::truncate_commit_message(&sanitized);

        let output = self
            .run_git_command(&["commit", "-m", &message], working_dir)
            .await;

        match output {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: format!("Committed: {message}").into(),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!("Commit failed: {e}")),
            }),
        }
    }

    async fn git_add(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let paths = args.get("paths").and_then(|v| v.as_str()).ok_or_else(|| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"param": "paths"})),
                "git_operations: missing paths parameter"
            );
            anyhow::Error::msg("Missing 'paths' parameter")
        })?;

        // Validate paths against injection patterns. Returns each
        // whitespace-separated pathspec as its own argument so the join is
        // not handed to git as a single literal path.
        let sanitized = self.sanitize_git_args(paths)?;
        if sanitized.is_empty() {
            anyhow::bail!("No paths to stage");
        }

        let mut git_args: Vec<&str> = vec!["add", "--"];
        git_args.extend(sanitized.iter().map(String::as_str));

        let output = self.run_git_command(&git_args, working_dir).await;

        match output {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: format!("Staged: {}", sanitized.join(" ")).into(),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!("Add failed: {e}")),
            }),
        }
    }

    async fn git_checkout(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let branch = args.get("branch").and_then(|v| v.as_str()).ok_or_else(|| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"param": "branch"})),
                "git_operations: missing branch parameter"
            );
            anyhow::Error::msg("Missing 'branch' parameter")
        })?;

        // Sanitize branch name
        let sanitized = self.sanitize_git_args(branch)?;

        if sanitized.is_empty() || sanitized.len() > 1 {
            anyhow::bail!("Invalid branch specification");
        }

        let branch_name = &sanitized[0];

        // Block dangerous branch names
        if branch_name.contains('@') || branch_name.contains('^') || branch_name.contains('~') {
            anyhow::bail!("Branch name contains invalid characters");
        }
        self.validate_revision(branch_name)?;

        let create_branch = args
            .get("create_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let track = args.get("track").and_then(|v| v.as_bool()).unwrap_or(false);

        if track && !branch_name.contains('/') {
            return Ok(Self::result_failure(Self::ferr(
                "tool-git-operations-error-checkout-track",
            )));
        }

        let mut git_args: Vec<&str> = vec!["checkout"];
        if create_branch {
            // For remote branches like "origin/feature", extract local name "feature".
            let local_name = if branch_name.contains('/') {
                branch_name.split('/').next_back().unwrap_or(branch_name)
            } else {
                branch_name
            };
            git_args.push("-b");
            git_args.push(local_name);
            if track {
                git_args.push("--track");
                git_args.push(branch_name);
            } else if branch_name.contains('/') {
                // Remote branch start point: create the local branch from the
                // remote-tracking ref so it starts at the remote tip, not HEAD.
                git_args.push(branch_name);
            }
        } else if track {
            git_args.push("--track");
            git_args.push(branch_name);
        } else {
            git_args.push(branch_name);
        }

        let output = self.run_git_command(&git_args, working_dir).await;

        match output {
            Ok(_) => Ok(Self::result_success(format!(
                "Switched to branch: {branch_name}"
            ))),
            Err(e) => Ok(Self::result_failure(format!("Checkout failed: {e}"))),
        }
    }

    async fn git_stash(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("push");

        let output = match action {
            "push" | "save" => {
                let message = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto-stash")
                    .to_string();
                let keep_index = args
                    .get("keep_index")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let include_untracked = args
                    .get("include_untracked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let paths_raw = args
                    .get("paths")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let mut cmd: Vec<String> =
                    vec!["stash".into(), "push".into(), "-m".into(), message];
                if keep_index {
                    cmd.push("-k".into());
                }
                if include_untracked {
                    cmd.push("-u".into());
                }
                if !paths_raw.is_empty() {
                    cmd.push("--".into());
                    for p in paths_raw.split_whitespace() {
                        cmd.push(p.to_string());
                    }
                }
                let cmd_refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                self.run_git_command(&cmd_refs, working_dir).await
            }
            "pop" => self.run_git_command(&["stash", "pop"], working_dir).await,
            "list" => self.run_git_command(&["stash", "list"], working_dir).await,
            "drop" => {
                let index_raw = args.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                let index = i32::try_from(index_raw).map_err(|_| {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({"index": index_raw})),
                        "git_operations: stash index too large"
                    );
                    anyhow::Error::msg(format!("stash index too large: {index_raw}"))
                })?;
                self.run_git_command(
                    &["stash", "drop", &format!("stash@{{{index}}}")],
                    working_dir,
                )
                .await
            }
            _ => anyhow::bail!("Unknown stash action: {action}. Use: push, pop, list, drop"),
        };

        match output {
            Ok(out) => Ok(ToolResult {
                success: true,
                output: out.into(),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!("Stash {action} failed: {e}")),
            }),
        }
    }

    fn parse_worktree_list(&self, output: &str) -> serde_json::Value {
        let mut worktrees = Vec::new();
        let mut current_path = String::new();
        let mut current_branch = String::new();
        let mut current_head = String::new();
        let mut is_detached = false;

        let workspace = self.workspace_dir.to_string_lossy();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                if !current_path.is_empty() {
                    worktrees.push(json!({
                        "path": &current_path,
                        "branch": if is_detached { "HEAD" } else { &current_branch },
                        "head": &current_head,
                        "detached": is_detached,
                        "active": current_path == workspace.as_ref()
                    }));
                    current_path.clear();
                    current_branch.clear();
                    current_head.clear();
                    is_detached = false;
                }
            } else if let Some(p) = line.strip_prefix("worktree ") {
                current_path = p.to_string();
            } else if let Some(h) = line.strip_prefix("HEAD ") {
                current_head = h.to_string();
            } else if let Some(b) = line.strip_prefix("branch ") {
                current_branch = b.trim_start_matches("refs/heads/").to_string();
            } else if line == "detached" {
                is_detached = true;
            }
        }
        // Flush final entry if output has no trailing blank line
        if !current_path.is_empty() {
            worktrees.push(json!({
                "path": &current_path,
                "branch": if is_detached { "HEAD" } else { current_branch.as_str() },
                "head": &current_head,
                "detached": is_detached,
                "active": current_path == workspace.as_ref()
            }));
        }

        json!({ "worktrees": worktrees })
    }

    async fn git_worktree(
        &self,
        args: serde_json::Value,
        working_dir: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let subcommand = match args.get("subcommand").and_then(|v| v.as_str()) {
            Some(cmd) => cmd,
            None => anyhow::bail!("Missing 'subcommand' parameter. Use: list, add, remove, prune"),
        };

        match subcommand {
            "list" => {
                let output = self
                    .run_git_command(&["worktree", "list", "--porcelain"], working_dir)
                    .await?;
                let parsed = self.parse_worktree_list(&output);
                Ok(ToolResult {
                    success: true,
                    output: serde_json::to_string_pretty(&parsed)
                        .unwrap_or_default()
                        .into(),
                    error: None,
                })
            }
            "add" => {
                let worktree_path = match args.get("worktree_path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => anyhow::bail!("Missing 'worktree_path' parameter for worktree add"),
                };
                self.sanitize_git_args(worktree_path)?;
                let worktree_path = self.ensure_worktree_add_target_allowed(worktree_path)?;
                let worktree_path = worktree_path.to_str().ok_or_else(|| {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure),
                        "git_operations: worktree path not valid UTF-8"
                    );
                    anyhow::Error::msg("Worktree path must be valid UTF-8 for git execution")
                })?;

                let branch = args
                    .get("branch")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                // git worktree add <path> [<branch>]
                let mut git_args = vec!["worktree", "add", worktree_path];
                if !branch.is_empty() {
                    self.sanitize_git_args(branch)?;
                    git_args.push(branch);
                }

                self.run_git_command(&git_args, working_dir).await?;
                Ok(ToolResult {
                    success: true,
                    output: format!("Worktree added at: {worktree_path}").into(),
                    error: None,
                })
            }
            "remove" => {
                let worktree_path = match args.get("worktree_path").and_then(|v| v.as_str()) {
                    Some(p) => p,
                    None => anyhow::bail!("Missing 'worktree_path' parameter for worktree remove"),
                };
                self.sanitize_git_args(worktree_path)?;
                let worktree_path = self.ensure_worktree_remove_target_allowed(worktree_path)?;
                let worktree_path = worktree_path.to_str().ok_or_else(|| {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure),
                        "git_operations: worktree path not valid UTF-8"
                    );
                    anyhow::Error::msg("Worktree path must be valid UTF-8 for git execution")
                })?;

                self.run_git_command(&["worktree", "remove", worktree_path], working_dir)
                    .await?;
                Ok(ToolResult {
                    success: true,
                    output: format!("Worktree removed: {worktree_path}").into(),
                    error: None,
                })
            }
            "prune" => {
                self.run_git_command(&["worktree", "prune"], working_dir)
                    .await?;
                Ok(ToolResult {
                    success: true,
                    output: "Worktree prune completed".to_string().into(),
                    error: None,
                })
            }
            _ => anyhow::bail!(
                "Unknown worktree subcommand: {subcommand}. Use: list, add, remove, prune"
            ),
        }
    }
}

#[async_trait]
impl Tool for GitOperationsTool {
    fn name(&self) -> &str {
        "git_operations"
    }

    fn description(&self) -> &str {
        TOOL_DESCRIPTION
            .get_or_init(|| crate::i18n::get_required_tool_string(TOOL_DESCRIPTION_KEY))
            .as_str()
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["status", "diff", "log", "branch", "commit", "add", "checkout", "stash", "worktree", "clone", "pull", "fetch"],
                    "description": "Git operation to perform"
                },
                "subcommand": {
                    "type": "string",
                    "enum": ["list", "add", "remove", "prune"],
                    "description": "Worktree subcommand"
                },
                "message": {
                    "type": "string",
                    "description": "Commit message (for 'commit' operation); stash message (for 'stash push', defaults to 'auto-stash')"
                },
                "paths": {
                    "type": "string",
                    "description": "Space-separated file paths. For 'add', files to stage. For 'stash push', pathspecs to scope the stash to — without this, the entire working tree is stashed."
                },
                "branch": {
                    "type": "string",
                    "description": "Branch name. For 'checkout' (optionally with create_branch/track) or 'worktree add'; also the upstream branch for 'pull'."
                },
                "worktree_path": {
                    "type": "string",
                    "description": "Filesystem path for the worktree (for 'worktree add' and 'worktree remove' subcommands). Relative paths resolve under the workspace; absolute paths must stay inside the workspace or configured allowed roots."
                },
                "files": {
                    "type": "string",
                    "description": "File or path to diff (for 'diff' operation, default: '.')"
                },
                "cached": {
                    "type": "boolean",
                    "description": "Show staged changes (for 'diff' operation)"
                },
                "commit": {
                    "type": "string",
                    "description": "Optional commit or revision to diff against (for 'diff' operation, e.g. 'HEAD~3' or 'HEAD~3..HEAD')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of log entries (for 'log' operation, default: 10)"
                },
                "action": {
                    "type": "string",
                    "enum": ["push", "pop", "list", "drop"],
                    "description": "Stash action (for 'stash' operation)"
                },
                "index": {
                    "type": "integer",
                    "description": "Stash index (for 'stash' with 'drop' action)"
                },
                "keep_index": {
                    "type": "boolean",
                    "description": "For 'stash push': preserve staged changes in the working tree after stashing — only unstaged changes go into the stash."
                },
                "include_untracked": {
                    "type": "boolean",
                    "description": "For 'stash push': also stash untracked files (-u). Without this, `git stash push` only touches tracked files."
                },
                "url": {
                    "type": "string",
                    "description": "Repository URL to clone (for 'clone'). Must be an https:// URL to a globally routable host; embedded credentials are rejected."
                },
                "destination": {
                    "type": "string",
                    "description": "Destination directory name for 'clone'. Defaults to the repository name derived from the URL."
                },
                "depth": {
                    "type": "integer",
                    "description": "Optional shallow-clone depth (positive integer) for 'clone'."
                },
                "remote": {
                    "type": "string",
                    "description": "Remote name. For 'fetch' (default: 'origin') or 'pull' to fetch from a specific remote."
                },
                "all": {
                    "type": "boolean",
                    "description": "For 'fetch': fetch from all remotes (cannot be combined with 'remote')."
                },
                "rebase": {
                    "type": "boolean",
                    "description": "For 'pull': rebase instead of merge."
                },
                "remote_branches": {
                    "type": "boolean",
                    "description": "For 'branch': list remote-tracking branches instead of local branches. Run 'fetch' first to refresh remote refs."
                },
                "create_branch": {
                    "type": "boolean",
                    "description": "For 'checkout': create the branch (-b) before switching."
                },
                "track": {
                    "type": "boolean",
                    "description": "For 'checkout': set up upstream tracking. Requires a remote branch name like 'origin/main'."
                },
                "path": {
                    "type": "string",
                    "description": "Optional subdirectory path within the workspace to run git operations in. Defaults to workspace root. For 'clone', this is the parent directory the repository is cloned into."
                }
            },
            "required": ["operation"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let operation = match args.get("operation").and_then(|v| v.as_str()) {
            Some(op) => op,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some("Missing 'operation' parameter".into()),
                });
            }
        };

        let path = args.get("path").and_then(|v| v.as_str());
        let working_dir = match self.resolve_working_dir(path) {
            Ok(d) => d,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(format!("Invalid path: {e}")),
                });
            }
        };

        // Check if we're in a git repository. Clone is the exception: it
        // creates the repository, so it must run outside an existing worktree.
        if operation != "clone" && !working_dir.join(".git").exists() {
            // Try to find .git in parent directories
            let mut current_dir = working_dir.as_path();
            let mut found_git = false;
            while current_dir.parent().is_some() {
                if current_dir.join(".git").exists() {
                    found_git = true;
                    break;
                }
                current_dir = current_dir.parent().unwrap();
            }

            if !found_git {
                let path_display = working_dir.display().to_string();
                let error_msg = crate::i18n::get_required_tool_string_with_args(
                    "tool-git-operations-error-not-in-repo",
                    &[("path", &path_display)],
                );
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(error_msg),
                });
            }
        }

        // Check autonomy level for write operations
        if self.requires_write_access(operation) {
            if !self.security.can_act() {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(
                        "Action blocked: git write operations require higher autonomy level".into(),
                    ),
                });
            }

            match self.security.autonomy {
                AutonomyLevel::ReadOnly => {
                    return Ok(ToolResult {
                        success: false,
                        output: ToolOutput::default(),
                        error: Some("Action blocked: read-only mode".into()),
                    });
                }
                AutonomyLevel::Supervised | AutonomyLevel::Full => {}
            }
        }

        // Record action for rate limiting
        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some("Action blocked: rate limit exceeded".into()),
            });
        }

        // Execute the requested operation
        match operation {
            "status" => self.git_status(args, &working_dir).await,
            "diff" => self.git_diff(args, &working_dir).await,
            "log" => self.git_log(args, &working_dir).await,
            "branch" => self.git_branch(args, &working_dir).await,
            "commit" => self.git_commit(args, &working_dir).await,
            "add" => self.git_add(args, &working_dir).await,
            "checkout" => self.git_checkout(args, &working_dir).await,
            "stash" => self.git_stash(args, &working_dir).await,
            "worktree" => self.git_worktree(args, &working_dir).await,
            "clone" => self.git_clone(args, &working_dir).await,
            "pull" => self.git_pull(args, &working_dir).await,
            "fetch" => self.git_fetch(args, &working_dir).await,
            _ => Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!("Unknown operation: {operation}")),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use zeroclaw_config::policy::SecurityPolicy;

    fn test_tool(dir: &std::path::Path) -> GitOperationsTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: dir.to_path_buf(),
            ..SecurityPolicy::default()
        });
        GitOperationsTool::new(security, dir.to_path_buf())
    }

    /// Initialise a git repo for tests with commit/tag signing disabled and a
    /// fixed identity. Tests run real `git commit`; without this they inherit
    /// the developer's global `commit.gpgsign`, blocking the suite on a
    /// hardware-key tap.
    fn git_init_no_sign(dir: &std::path::Path, extra_init: &[&str]) {
        let mut init = vec!["init"];
        init.extend_from_slice(extra_init);
        for args in [
            init.as_slice(),
            &["config", "user.email", "test@test.com"],
            &["config", "user.name", "Test"],
            &["config", "commit.gpgsign", "false"],
            &["config", "tag.gpgsign", "false"],
        ] {
            std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
        }
    }

    fn test_tool_with_allowed_root(
        dir: &std::path::Path,
        allowed_root: std::path::PathBuf,
    ) -> GitOperationsTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: dir.to_path_buf(),
            allowed_roots: vec![allowed_root],
            ..SecurityPolicy::default()
        });
        GitOperationsTool::new(security, dir.to_path_buf())
    }

    #[test]
    fn sanitize_git_blocks_injection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        // Should block dangerous arguments
        assert!(tool.sanitize_git_args("--exec=rm -rf /").is_err());
        assert!(tool.sanitize_git_args("$(echo pwned)").is_err());
        assert!(tool.sanitize_git_args("`malicious`").is_err());
        assert!(tool.sanitize_git_args("arg | cat").is_err());
        assert!(tool.sanitize_git_args("arg; rm file").is_err());
    }

    #[test]
    fn sanitize_git_blocks_pager_editor_injection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.sanitize_git_args("--pager=less").is_err());
        assert!(tool.sanitize_git_args("--editor=vim").is_err());
    }

    #[test]
    fn sanitize_git_blocks_config_injection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        // Exact `-c` flag (config injection)
        assert!(tool.sanitize_git_args("-c core.sshCommand=evil").is_err());
        assert!(tool.sanitize_git_args("-c=core.pager=less").is_err());
    }

    #[test]
    fn sanitize_git_blocks_no_verify() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.sanitize_git_args("--no-verify").is_err());
    }

    #[test]
    fn sanitize_git_blocks_redirect_in_args() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.sanitize_git_args("file.txt > /tmp/out").is_err());
    }

    #[test]
    fn sanitize_git_cached_not_blocked() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        // --cached must NOT be blocked by the `-c` check
        assert!(tool.sanitize_git_args("--cached").is_ok());
        // Other safe flags starting with -c prefix
        assert!(tool.sanitize_git_args("-cached").is_ok());
    }

    #[test]
    fn worktree_add_target_must_stay_inside_workspace_or_allowed_root() {
        let workspace = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let tool = test_tool(workspace.path());

        assert!(
            tool.ensure_worktree_add_target_allowed("new-worktree")
                .is_ok()
        );
        assert!(
            tool.ensure_worktree_add_target_allowed(
                outside.path().join("new-worktree").to_str().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn worktree_add_target_allows_configured_allowed_root() {
        let workspace = TempDir::new().unwrap();
        let allowed = TempDir::new().unwrap();
        let tool = test_tool_with_allowed_root(workspace.path(), allowed.path().to_path_buf());

        assert!(
            tool.ensure_worktree_add_target_allowed(
                allowed.path().join("new-worktree").to_str().unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn worktree_remove_target_must_stay_inside_workspace() {
        let workspace = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::create_dir(workspace.path().join("old-worktree")).unwrap();
        std::fs::create_dir(outside.path().join("old-worktree")).unwrap();
        let tool = test_tool(workspace.path());

        assert!(
            tool.ensure_worktree_remove_target_allowed("old-worktree")
                .is_ok()
        );
        assert!(
            tool.ensure_worktree_remove_target_allowed(
                outside.path().join("old-worktree").to_str().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn sanitize_git_allows_safe() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        // Should allow safe arguments
        assert!(tool.sanitize_git_args("main").is_ok());
        assert!(tool.sanitize_git_args("feature/test-branch").is_ok());
        assert!(tool.sanitize_git_args("--cached").is_ok());
        assert!(tool.sanitize_git_args("src/main.rs").is_ok());
        assert!(tool.sanitize_git_args(".").is_ok());
    }

    #[test]
    fn requires_write_detection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.requires_write_access("commit"));
        assert!(tool.requires_write_access("add"));
        assert!(tool.requires_write_access("checkout"));
        assert!(tool.requires_write_access("stash"));
        assert!(tool.requires_write_access("worktree"));
        assert!(tool.requires_write_access("clone"));
        assert!(tool.requires_write_access("pull"));

        assert!(!tool.requires_write_access("status"));
        assert!(!tool.requires_write_access("diff"));
        assert!(!tool.requires_write_access("log"));
        assert!(!tool.requires_write_access("branch"));
        assert!(!tool.requires_write_access("fetch"));
    }

    #[test]
    fn is_read_only_detection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.is_read_only("status"));
        assert!(tool.is_read_only("diff"));
        assert!(tool.is_read_only("log"));
        assert!(tool.is_read_only("branch"));
        assert!(tool.is_read_only("fetch"));

        // worktree has write subcommands (add/remove), so it is not read-only
        assert!(!tool.is_read_only("worktree"));
        assert!(!tool.is_read_only("commit"));
        assert!(!tool.is_read_only("add"));
        assert!(!tool.is_read_only("clone"));
        assert!(!tool.is_read_only("pull"));
    }

    #[test]
    fn branch_is_not_write_gated() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        // Branch listing is read-only; it must not require write access
        assert!(!tool.requires_write_access("branch"));
        assert!(tool.is_read_only("branch"));
    }

    #[tokio::test]
    async fn git_credential_op_fails_fast_without_terminal_prompt() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);
        let tool = test_tool(tmp.path());

        let fetch = tool.run_git_command(
            &["fetch", "https://127.0.0.1:1/private/repo.git"],
            tmp.path(),
        );
        let res = tokio::time::timeout(std::time::Duration::from_secs(10), fetch).await;

        assert!(
            res.is_ok(),
            "git fetch hung — it likely prompted for credentials on the terminal"
        );
        assert!(
            res.unwrap().is_err(),
            "fetch to an unreachable private remote should fail, not succeed"
        );
    }

    #[tokio::test]
    async fn blocks_readonly_mode_for_write_ops() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool
            .execute(json!({"operation": "commit", "message": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        // can_act() returns false for ReadOnly, so we get the "higher autonomy level" message
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("higher autonomy")
        );
    }

    #[tokio::test]
    async fn allows_branch_listing_in_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool.execute(json!({"operation": "branch"})).await.unwrap();
        // Branch listing must not be blocked by read-only autonomy
        let error_msg = result.error.as_deref().unwrap_or("");
        assert!(
            !error_msg.contains("read-only") && !error_msg.contains("higher autonomy"),
            "branch listing should not be blocked in read-only mode, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn allows_readonly_ops_in_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        // This will fail because there's no git repo, but it shouldn't be blocked by autonomy
        let result = tool.execute(json!({"operation": "status"})).await.unwrap();
        // The error should be about git (not about autonomy/read-only mode)
        assert!(!result.success, "Expected failure due to missing git repo");
        let error_msg = result.error.as_deref().unwrap_or("");
        assert!(
            !error_msg.contains("read-only") && !error_msg.contains("autonomy"),
            "Error should be about git, not about autonomy restrictions: {error_msg}"
        );
    }

    #[tokio::test]
    async fn rejects_missing_operation() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool.execute(json!({})).await.unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Missing 'operation'")
        );
    }

    #[tokio::test]
    async fn rejects_unknown_operation() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);

        let tool = test_tool(tmp.path());

        let result = tool.execute(json!({"operation": "push"})).await.unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Unknown operation")
        );
    }

    #[tokio::test]
    async fn commit_message_preserves_blank_line_between_subject_and_body() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);
        // Create an initial commit so HEAD exists.
        std::fs::write(tmp.path().join("README.md"), "hello").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let msg = "fix(foo): subject line\n\nThis is the body paragraph.\n\nSecond paragraph.";
        let result = tool
            .execute(json!({"operation": "commit", "message": msg}))
            .await
            .unwrap();
        assert!(result.success, "commit failed: {:?}", result.error);

        // Read back the raw commit message via git log.
        let log_out = std::process::Command::new("git")
            .args(["log", "-1", "--format=%B"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let log_msg = String::from_utf8_lossy(&log_out.stdout);

        // Subject line must be on its own line.
        assert!(
            log_msg.starts_with("fix(foo): subject line\n"),
            "subject line missing or not first: {log_msg:?}"
        );
        // A blank line must follow the subject.
        assert!(
            log_msg.contains("fix(foo): subject line\n\n"),
            "blank line between subject and body missing: {log_msg:?}"
        );
        // Body text must be present.
        assert!(
            log_msg.contains("This is the body paragraph."),
            "body paragraph missing: {log_msg:?}"
        );
    }

    #[test]
    fn truncates_multibyte_commit_message_without_panicking() {
        let long = "🦀".repeat(2500);
        let truncated = GitOperationsTool::truncate_commit_message(&long);

        assert_eq!(truncated.chars().count(), 2000);
    }

    #[test]
    fn resolve_working_dir_none_returns_workspace() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool.resolve_working_dir(None).unwrap();
        assert_eq!(result, tmp.path().to_path_buf());
    }

    #[test]
    fn resolve_working_dir_empty_returns_workspace() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool.resolve_working_dir(Some("")).unwrap();
        assert_eq!(result, tmp.path().to_path_buf());
    }

    #[test]
    fn resolve_working_dir_valid_subdir() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("subproject")).unwrap();
        let tool = test_tool(tmp.path());

        let result = tool.resolve_working_dir(Some("subproject")).unwrap();
        let expected = tmp.path().join("subproject").canonicalize().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn resolve_working_dir_rejects_traversal() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool.resolve_working_dir(Some(".."));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("resolves outside the workspace"),
            "Expected traversal rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn git_operations_work_in_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("nested");
        std::fs::create_dir(&sub).unwrap();
        git_init_no_sign(&sub, &[]);

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "status", "path": "nested"}))
            .await
            .unwrap();
        assert!(
            result.success,
            "Expected success, got error: {:?}",
            result.error
        );
        assert!(result.output.contains("branch"));
    }

    #[tokio::test]
    async fn git_worktree_list_works() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "worktree", "subcommand": "list"}))
            .await
            .unwrap();
        assert!(result.success, "Expected success, got: {:?}", result.error);

        let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let worktrees = parsed["worktrees"]
            .as_array()
            .expect("worktrees must be an array");
        assert!(
            !worktrees.is_empty(),
            "Expected at least the main worktree in the list"
        );
        assert!(
            worktrees[0]["path"].as_str().is_some_and(|p| !p.is_empty()),
            "Main worktree must have a non-empty path"
        );
    }

    async fn bootstrap_repo(dir: &std::path::Path, tracked_files: &[&str]) {
        git_init_no_sign(dir, &["-b", "master"]);
        std::fs::write(dir.join("README.md"), "hello").unwrap();
        for f in tracked_files {
            std::fs::write(dir.join(f), "initial").unwrap();
        }
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir)
            .output()
            .unwrap();
    }

    /// Run `git <args>` in `dir`, panicking on failure. Used to seed
    /// repositories and remotes that the tool then operates on.
    fn run_git(dir: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
        assert!(
            output.status.success(),
            "git {args:?} failed: {}\nbranches:\n{}\nhead: {}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(
                &std::process::Command::new("git")
                    .args(["branch", "-a", "--verbose"])
                    .current_dir(dir)
                    .output()
                    .map(|o| o.stdout)
                    .unwrap_or_default()
            ),
            String::from_utf8_lossy(
                &std::process::Command::new("git")
                    .args(["rev-parse", "--abbrev-ref", "HEAD"])
                    .current_dir(dir)
                    .output()
                    .map(|o| o.stdout)
                    .unwrap_or_default()
            )
        );
    }

    #[tokio::test]
    async fn stash_push_default_stashes_staged_and_unstaged() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &["staged.txt", "unstaged.txt"]).await;

        std::fs::write(tmp.path().join("staged.txt"), "s-modified").unwrap();
        std::fs::write(tmp.path().join("unstaged.txt"), "u-modified").unwrap();
        std::process::Command::new("git")
            .args(["add", "staged.txt"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({"operation": "stash", "action": "push"}))
            .await
            .unwrap();
        assert!(result.success, "stash push failed: {:?}", result.error);

        let status = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let status_out = String::from_utf8_lossy(&status.stdout);
        assert!(
            status_out.trim().is_empty(),
            "expected clean working tree after default stash, got: {status_out:?}"
        );
    }

    #[tokio::test]
    async fn stash_push_with_keep_index_preserves_staged() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &["staged.txt", "unstaged.txt"]).await;

        std::fs::write(tmp.path().join("staged.txt"), "s-modified").unwrap();
        std::fs::write(tmp.path().join("unstaged.txt"), "u-modified").unwrap();
        std::process::Command::new("git")
            .args(["add", "staged.txt"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({
                "operation": "stash",
                "action": "push",
                "keep_index": true,
            }))
            .await
            .unwrap();
        assert!(result.success, "stash push -k failed: {:?}", result.error);

        let status = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let status_out = String::from_utf8_lossy(&status.stdout).to_string();
        // `staged.txt` modification still present and staged (`M ` prefix);
        // `unstaged.txt` modification was stashed away — file matches HEAD.
        assert!(
            status_out.contains("M  staged.txt"),
            "staged modification should remain staged, status: {status_out:?}"
        );
        assert!(
            !status_out.contains("unstaged.txt"),
            "unstaged modification should have been stashed, status: {status_out:?}"
        );
    }

    #[tokio::test]
    async fn stash_push_with_paths_scopes_to_pathspec() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &["a.txt", "b.txt"]).await;

        std::fs::write(tmp.path().join("a.txt"), "a-modified").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "b-modified").unwrap();

        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({
                "operation": "stash",
                "action": "push",
                "paths": "a.txt",
            }))
            .await
            .unwrap();
        assert!(
            result.success,
            "stash push -- a.txt failed: {:?}",
            result.error
        );

        let status = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let status_out = String::from_utf8_lossy(&status.stdout).to_string();
        assert!(
            !status_out.contains("a.txt"),
            "a.txt should have been stashed, status: {status_out:?}"
        );
        assert!(
            status_out.contains("b.txt"),
            "b.txt should remain modified, status: {status_out:?}"
        );
    }

    #[tokio::test]
    async fn stash_push_with_custom_message() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &["a.txt"]).await;
        std::fs::write(tmp.path().join("a.txt"), "a-modified").unwrap();

        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({
                "operation": "stash",
                "action": "push",
                "message": "scoped-fix-wip",
            }))
            .await
            .unwrap();
        assert!(result.success, "stash push -m failed: {:?}", result.error);

        let list = std::process::Command::new("git")
            .args(["stash", "list"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let list_out = String::from_utf8_lossy(&list.stdout).to_string();
        assert!(
            list_out.contains("scoped-fix-wip"),
            "custom stash message missing from list, got: {list_out:?}"
        );
    }

    #[tokio::test]
    async fn stash_push_with_include_untracked_captures_new_files() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        std::fs::write(tmp.path().join("new.txt"), "untracked").unwrap();

        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({
                "operation": "stash",
                "action": "push",
                "include_untracked": true,
            }))
            .await
            .unwrap();
        assert!(result.success, "stash push -u failed: {:?}", result.error);

        let status = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let status_out = String::from_utf8_lossy(&status.stdout);
        assert!(
            status_out.trim().is_empty(),
            "expected clean tree after -u stash, got: {status_out:?}"
        );
    }

    #[tokio::test]
    async fn add_stages_multiple_space_separated_paths() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);
        std::fs::write(tmp.path().join("a.txt"), "a").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "b").unwrap();

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            workspace_dir: tmp.path().to_path_buf(),
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool
            .execute(json!({"operation": "add", "paths": "a.txt b.txt"}))
            .await
            .unwrap();
        assert!(result.success, "add failed: {:?}", result.error);

        let status = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&status.stdout);
        assert!(out.contains("A  a.txt"), "a.txt not staged: {out:?}");
        assert!(out.contains("A  b.txt"), "b.txt not staged: {out:?}");
    }

    #[tokio::test]
    async fn non_repository_error_includes_path_context_and_recovery_hint() {
        let tmp = TempDir::new().unwrap();
        // Do NOT git-init the temp dir — we want a non-repository path.
        let tool = test_tool(tmp.path());

        let result = tool.execute(json!({"operation": "status"})).await.unwrap();

        assert!(
            !result.success,
            "git_operations should fail when not in a repository"
        );

        let error = result.error.as_deref().unwrap_or("");
        let path_display = tmp.path().display().to_string();

        // The error message must include the resolved working directory
        // path so the user can see where the tool was looking.
        assert!(
            error.contains(&path_display),
            "error should contain the working directory path '{path_display}', got: {error}"
        );

        // The error message must include recovery guidance keywords
        // that tell the user how to resolve the issue.
        assert!(
            error.contains("worktree") || error.contains("work tree") || error.contains("path"),
            "error should contain a recovery keyword (worktree/work tree/path), got: {error}"
        );
        assert!(
            error.contains("initialize") || error.contains("init"),
            "error should mention initializing a repository, got: {error}"
        );
    }

    #[test]
    fn remote_name_validation() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.validate_remote_name("origin").is_ok());
        assert!(tool.validate_remote_name("upstream-2").is_ok());
        assert!(tool.validate_remote_name("").is_err());
        assert!(tool.validate_remote_name("-origin").is_err());
        assert!(tool.validate_remote_name("--upload-pack=evil").is_err());
        assert!(tool.validate_remote_name("origin repo").is_err());
        assert!(tool.validate_remote_name("o;rm -rf").is_err());
    }

    #[test]
    fn revision_validation_rejects_option_injection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.validate_revision("HEAD").is_ok());
        assert!(tool.validate_revision("main").is_ok());
        assert!(tool.validate_revision("v1.2.3~1").is_ok());
        assert!(tool.validate_revision("").is_err());
        // A leading `-` would be parsed as a git option (e.g. `git diff --output=...`).
        assert!(tool.validate_revision("-x").is_err());
        assert!(tool.validate_revision("--output=/tmp/x").is_err());
        assert!(tool.validate_revision("HEAD;rm -rf /").is_err());
        assert!(tool.validate_revision("HEAD | cat").is_err());
        assert!(tool.validate_revision("HEAD`id`").is_err());
        assert!(tool.validate_revision("HEAD\nreset").is_err());
    }

    #[test]
    fn destination_component_validation() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.validate_destination_component("myproject").is_ok());
        assert!(tool.validate_destination_component("repo-name_2").is_ok());
        assert!(tool.validate_destination_component("").is_err());
        assert!(tool.validate_destination_component(".").is_err());
        assert!(tool.validate_destination_component("..").is_err());
        assert!(tool.validate_destination_component("../escape").is_err());
        assert!(tool.validate_destination_component("a/b").is_err());
        assert!(tool.validate_destination_component("a\\b").is_err());
        assert!(tool.validate_destination_component("/abs").is_err());
        assert!(tool.validate_destination_component("~home").is_err());
        assert!(tool.validate_destination_component("-flag").is_err());
        assert!(tool.validate_destination_component(".hidden").is_err());
        assert!(tool.validate_destination_component("has space").is_err());
    }

    #[test]
    fn clone_url_validation() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(
            tool.validate_clone_url("https://github.com/org/repo.git")
                .is_ok()
        );
        assert!(
            tool.validate_clone_url(" https://github.com/org/repo.git ")
                .is_ok()
        );
        assert!(tool.validate_clone_url("").is_err());
        assert!(tool.validate_clone_url("not a url").is_err());
        assert!(tool.validate_clone_url("https://").is_err());
        // Non-https schemes
        assert!(
            tool.validate_clone_url("http://example.com/repo.git")
                .is_err()
        );
        assert!(
            tool.validate_clone_url("git://example.com/repo.git")
                .is_err()
        );
        assert!(tool.validate_clone_url("file:///etc/passwd").is_err());
        assert!(
            tool.validate_clone_url("ssh://git@example.com/repo.git")
                .is_err()
        );
        // Embedded credentials
        assert!(
            tool.validate_clone_url("https://user:pass@example.com/repo.git")
                .is_err()
        );
        assert!(
            tool.validate_clone_url("https://token@example.com/repo.git")
                .is_err()
        );
        // Local/private hosts (SSRF guard)
        assert!(
            tool.validate_clone_url("https://127.0.0.1/repo.git")
                .is_err()
        );
        assert!(
            tool.validate_clone_url("https://localhost/repo.git")
                .is_err()
        );
        assert!(tool.validate_clone_url("https://[::1]/repo.git").is_err());
        assert!(
            tool.validate_clone_url("https://10.0.0.5/repo.git")
                .is_err()
        );
        assert!(
            tool.validate_clone_url("https://192.168.1.1/repo.git")
                .is_err()
        );
        // Cloud metadata endpoints
        assert!(
            tool.validate_clone_url("https://169.254.169.254/latest/meta-data")
                .is_err()
        );
        assert!(
            tool.validate_clone_url("https://100.100.100.200/latest/meta-data")
                .is_err()
        );
    }

    #[test]
    fn extract_destination_from_url_deduces_repo_name() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());
        let _ = tool;

        assert_eq!(
            GitOperationsTool::extract_destination_from_url("https://github.com/org/my-repo.git"),
            "my-repo"
        );
        assert_eq!(
            GitOperationsTool::extract_destination_from_url("https://github.com/org/repo"),
            "repo"
        );
        assert_eq!(
            GitOperationsTool::extract_destination_from_url("https://github.com"),
            "repo"
        );
    }

    #[test]
    fn resolve_clone_target_rejects_existing_destination() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());
        std::fs::create_dir(tmp.path().join("exists")).unwrap();

        assert!(tool.resolve_clone_target(None, "exists").is_err());
        assert!(tool.resolve_clone_target(None, "fresh").is_ok());
    }

    #[test]
    fn clone_destination_cannot_escape_workspace() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        // Any component that could escape the workspace or smuggle a flag is
        // rejected before path resolution, so resolve_clone_target cannot be
        // reached with a dangerous destination.
        for dest in [
            "..",
            "../escape",
            ".",
            "/abs",
            "~",
            "-flag",
            "a/b",
            ".hidden",
            "has space",
        ] {
            assert!(
                tool.validate_destination_component(dest).is_err(),
                "should reject destination '{dest}'"
            );
        }
    }

    #[tokio::test]
    async fn clone_is_write_gated_and_blocked_in_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            workspace_dir: tmp.path().to_path_buf(),
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "https://github.com/org/repo.git",
                "destination": "repo"
            }))
            .await
            .unwrap();
        assert!(!result.success, "clone must be write-gated");
        let error = result.error.as_deref().unwrap_or("");
        assert!(
            error.contains("blocked"),
            "write gating should block clone, got: {error}"
        );
    }

    #[tokio::test]
    async fn clone_rejects_non_https_and_unsafe_hosts() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        for url in [
            "git://github.com/org/repo.git",
            "http://github.com/org/repo.git",
            "file:///etc/passwd",
            "ssh://git@github.com/org/repo.git",
            "https://127.0.0.1/org/repo.git",
            "https://localhost/org/repo.git",
            "https://10.0.0.5/org/repo.git",
            "https://169.254.169.254/latest/meta-data",
            "https://user:pass@github.com/org/repo.git",
            "https://token@github.com/org/repo.git",
            "https://github.com/org/repo with space.git",
        ] {
            let result = tool
                .execute(json!({
                    "operation": "clone",
                    "url": url,
                    "destination": "repo"
                }))
                .await
                .unwrap();
            assert!(
                !result.success,
                "clone should reject URL {url} before touching the network"
            );
        }
    }

    #[tokio::test]
    async fn clone_rejects_zero_depth() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "https://github.com/org/repo.git",
                "destination": "repo",
                "depth": 0
            }))
            .await
            .unwrap();
        assert!(!result.success, "depth=0 must be rejected");
    }

    #[tokio::test]
    async fn clone_works_at_network_command_boundary() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        let tool = test_tool(tmp.path());
        let dest = tmp.path().join("cloned");
        let url = format!("file://{}", tmp.path().display());

        // The tool-level `clone` refuses file:// URLs, so prove the scrubbed
        // network command itself can clone: this is the boundary the real
        // https clone would exercise.
        let output = tool
            .run_network_git_command(&["clone", &url, dest.to_str().unwrap()], tmp.path())
            .await
            .expect("scrubbed-env git clone should succeed");
        assert!(
            output.is_empty() || output.contains("Cloning"),
            "unexpected clone output: {output}"
        );
        assert!(
            dest.join(".git").exists(),
            "clone should create the target repo"
        );
        assert!(
            dest.join("README.md").exists(),
            "clone should materialize files"
        );
    }

    #[tokio::test]
    async fn network_git_ignores_ambient_git_config() {
        let tmp = TempDir::new().unwrap();
        git_init_no_sign(tmp.path(), &[]);
        let tool = test_tool(tmp.path());

        let output = tool
            .run_network_git_command(&["config", "--list", "--show-origin"], tmp.path())
            .await
            .unwrap();

        // System/global gitconfig must be disabled (GIT_CONFIG_NOSYSTEM=1 and
        // GIT_CONFIG_GLOBAL=/dev/null); only repo-local config and the injected
        // `-c safe.directory` line may show up.
        assert!(
            !output.contains("global") && !output.contains("system"),
            "network git must not read system/global config, got:\n{output}"
        );
    }

    #[tokio::test]
    async fn fetch_all_and_remote_cannot_be_combined() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "fetch", "all": true, "remote": "origin"}))
            .await
            .unwrap();
        assert!(
            !result.success,
            "fetch with both 'all' and 'remote' must fail"
        );
    }

    #[tokio::test]
    async fn fetch_is_not_blocked_in_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            workspace_dir: tmp.path().to_path_buf(),
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        // No remote is configured, so git fails — but the read-only policy
        // itself must not block a fetch.
        let result = tool
            .execute(json!({"operation": "fetch", "remote": "origin"}))
            .await
            .unwrap();
        assert!(!result.success);
        let error = result.error.as_deref().unwrap_or("");
        assert!(
            !error.contains("read-only"),
            "fetch must not be blocked by read-only mode, got: {error}"
        );
        assert!(
            error.contains("origin"),
            "fetch should have reached git and failed on the missing remote, got: {error}"
        );
    }

    #[tokio::test]
    async fn pull_rejects_invalid_remote_or_branch() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "pull", "remote": "-evil", "branch": "main"}))
            .await
            .unwrap();
        assert!(
            !result.success,
            "pull must reject a flag-shaped remote name"
        );
        assert!(
            result.error.as_deref().unwrap_or("").contains("remote"),
            "error should name the remote problem"
        );

        let result = tool
            .execute(json!({"operation": "pull", "remote": "origin", "branch": "--output=/x"}))
            .await
            .unwrap();
        assert!(
            !result.success,
            "pull must reject option injection in branch"
        );
        assert!(
            result.error.as_deref().unwrap_or("").contains("--output"),
            "error should surface the injected branch value"
        );
    }

    #[tokio::test]
    async fn fetch_pull_and_remote_branches_with_local_remote() {
        let tmp = TempDir::new().unwrap();

        // Bare remote hosted on the local filesystem (no real network needed).
        // Default the remote HEAD to `master` so later `git clone` produces a
        // local `master` branch that matches the branches we push.
        let bare = tmp.path().join("remote.git");
        std::fs::create_dir(&bare).unwrap();
        git_init_no_sign(&bare, &["--bare", "-b", "master"]);

        // Repo A: publishes the first commit.
        let dev_a = tmp.path().join("dev-a");
        std::fs::create_dir(&dev_a).unwrap();
        git_init_no_sign(&dev_a, &["-b", "master"]);
        std::fs::write(dev_a.join("file.txt"), "one").unwrap();
        run_git(&dev_a, &["add", "."]);
        run_git(&dev_a, &["commit", "-m", "first"]);
        run_git(&dev_a, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dev_a, &["push", "-u", "origin", "master"]);

        // Repo B: advances the shared remote with a second commit. Clone does
        // not inherit the no-sign/identity local config, so set it explicitly
        // (mirrors git_init_no_sign) to avoid the developer's gpg signing.
        let dev_b = tmp.path().join("dev-b");
        std::process::Command::new("git")
            .args(["clone", bare.to_str().unwrap(), dev_b.to_str().unwrap()])
            .output()
            .unwrap();
        run_git(&dev_b, &["config", "user.email", "test@test.com"]);
        run_git(&dev_b, &["config", "user.name", "Test"]);
        run_git(&dev_b, &["config", "commit.gpgsign", "false"]);
        run_git(&dev_b, &["config", "tag.gpgsign", "false"]);
        std::fs::write(dev_b.join("file.txt"), "two").unwrap();
        run_git(&dev_b, &["add", "."]);
        run_git(&dev_b, &["commit", "-m", "second"]);
        run_git(&dev_b, &["push", "-u", "origin", "master"]);

        let tool = test_tool(&dev_a);

        let result = tool.execute(json!({"operation": "fetch"})).await.unwrap();
        assert!(result.success, "fetch failed: {:?}", result.error);

        let result = tool
            .execute(json!({"operation": "branch", "remote_branches": true}))
            .await
            .unwrap();
        assert!(result.success, "remote branch listing failed");
        assert!(
            result.output.contains("origin/master"),
            "expected origin/master after fetch, got: {}",
            result.output
        );

        let result = tool.execute(json!({"operation": "pull"})).await.unwrap();
        assert!(result.success, "pull failed: {:?}", result.error);

        let file = std::fs::read_to_string(dev_a.join("file.txt")).unwrap();
        assert_eq!(
            file, "two",
            "pull should fast-forward dev-a to the second commit"
        );
    }

    #[tokio::test]
    async fn checkout_create_branch_and_track() {
        let tmp = TempDir::new().unwrap();
        let bare = tmp.path().join("remote.git");
        std::fs::create_dir(&bare).unwrap();
        git_init_no_sign(&bare, &["--bare"]);

        // Seed the remote with branches that have no local counterparts yet.
        let seed = tmp.path().join("seed");
        std::fs::create_dir(&seed).unwrap();
        git_init_no_sign(&seed, &["-b", "master"]);
        std::fs::write(seed.join("f.txt"), "feature").unwrap();
        run_git(&seed, &["add", "."]);
        run_git(&seed, &["commit", "-m", "seed"]);
        run_git(&seed, &["branch", "feature"]);
        run_git(&seed, &["branch", "topic"]);
        run_git(&seed, &["branch", "extra"]);
        run_git(&seed, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(
            &seed,
            &[
                "push", "-u", "origin", "master", "feature", "topic", "extra",
            ],
        );

        let repo = tmp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        git_init_no_sign(&repo, &["-b", "master"]);
        std::fs::write(repo.join("m.txt"), "master").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "master"]);
        run_git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);

        let tool = test_tool(&repo);
        let result = tool.execute(json!({"operation": "fetch"})).await.unwrap();
        assert!(result.success, "fetch failed: {:?}", result.error);

        // create_branch extracts the local name from the remote branch.
        let result = tool
            .execute(json!({
                "operation": "checkout",
                "branch": "origin/feature",
                "create_branch": true
            }))
            .await
            .unwrap();
        assert!(result.success, "checkout failed: {:?}", result.error);
        let current_output = std::process::Command::new("git")
            .args(["branch", "--show-current"])
            .current_dir(&repo)
            .output()
            .unwrap();
        let current = String::from_utf8_lossy(&current_output.stdout);
        assert_eq!(current.trim(), "feature");
        assert!(
            std::fs::read_to_string(repo.join("f.txt"))
                .unwrap()
                .contains("feature")
        );

        // create_branch + track also sets an upstream.
        let result = tool
            .execute(json!({
                "operation": "checkout",
                "branch": "origin/topic",
                "create_branch": true,
                "track": true
            }))
            .await
            .unwrap();
        assert!(
            result.success,
            "checkout create+track failed: {:?}",
            result.error
        );
        let topic_output = std::process::Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "topic@{upstream}"])
            .current_dir(&repo)
            .output()
            .unwrap();
        let upstream = String::from_utf8_lossy(&topic_output.stdout);
        assert_eq!(upstream.trim(), "origin/topic");

        // track without create also creates the local branch.
        let result = tool
            .execute(json!({
                "operation": "checkout",
                "branch": "origin/extra",
                "track": true
            }))
            .await
            .unwrap();
        assert!(result.success, "checkout track failed: {:?}", result.error);
        let extra_output = std::process::Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "extra@{upstream}"])
            .current_dir(&repo)
            .output()
            .unwrap();
        let upstream = String::from_utf8_lossy(&extra_output.stdout);
        assert_eq!(upstream.trim(), "origin/extra");
    }

    #[tokio::test]
    async fn checkout_track_requires_remote_branch_name() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        let tool = test_tool(tmp.path());

        // track=true without a remote branch name fails fast (no network).
        let result = tool
            .execute(json!({"operation": "checkout", "branch": "feature", "track": true}))
            .await
            .unwrap();
        assert!(!result.success, "track without a remote branch must fail");
        let error = result.error.as_deref().unwrap_or("");
        assert!(
            error.contains("track") && error.contains("origin"),
            "error should explain track needs a remote branch, got: {error}"
        );

        // track=true with a nonexistent remote branch fails via git.
        let result = tool
            .execute(json!({
                "operation": "checkout",
                "branch": "origin/missing",
                "track": true
            }))
            .await
            .unwrap();
        assert!(
            !result.success,
            "tracking a missing remote branch must fail"
        );
    }

    #[tokio::test]
    async fn diff_accepts_commit_revision_and_rejects_option_injection() {
        let tmp = TempDir::new().unwrap();
        bootstrap_repo(tmp.path(), &[]).await;
        std::fs::write(tmp.path().join("feature.txt"), "feature").unwrap();
        run_git(tmp.path(), &["add", "."]);
        run_git(tmp.path(), &["commit", "-m", "second"]);

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "diff", "commit": "HEAD~1"}))
            .await
            .unwrap();
        assert!(result.success, "diff failed: {:?}", result.error);
        assert!(
            result.output.contains("feature.txt"),
            "expected feature.txt in the diff, got: {}",
            result.output
        );

        assert!(
            tool.execute(json!({"operation": "diff", "commit": "--output=/etc/passwd"}))
                .await
                .is_err(),
            "diff must reject option injection via the commit parameter"
        );
    }
}
