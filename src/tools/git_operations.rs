use super::traits::{Tool, ToolResult};
use crate::security::{AutonomyLevel, SecurityPolicy};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

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
            "commit" | "add" | "checkout" | "stash" | "reset" | "revert" | "clone" | "pull"
        )
    }

    /// Check if an operation is read-only
    fn is_read_only(&self, operation: &str) -> bool {
        matches!(
            operation,
            "status" | "diff" | "log" | "show" | "branch" | "rev-parse" | "fetch"
        )
    }

    async fn run_git_command(
        &self,
        args: &[&str],
        cwd: &std::path::Path,
    ) -> anyhow::Result<String> {
        let output = tokio::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
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
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let output = self
            .run_git_command(&["status", "--porcelain=2", "--branch"], cwd)
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
                if let (Some(staging), Some(path)) = (parts.next(), parts.next()) {
                    if !staging.is_empty() {
                        let status_char = staging.chars().next().unwrap_or(' ');
                        if status_char != '.' && status_char != ' ' {
                            staged.push(json!({"path": path, "status": status_char}));
                        }
                        let status_char = staging.chars().nth(1).unwrap_or(' ');
                        if status_char != '.' && status_char != ' ' {
                            unstaged.push(json!({"path": path, "status": status_char}));
                        }
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
            output: serde_json::to_string_pretty(&result).unwrap_or_default(),
            error: None,
        })
    }

    async fn git_diff(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let files = args.get("files").and_then(|v| v.as_str()).unwrap_or(".");
        let cached = args
            .get("cached")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let commit = args.get("commit").and_then(|v| v.as_str());

        // Validate files argument against injection patterns
        self.sanitize_git_args(files)?;
        if let Some(c) = commit {
            self.sanitize_git_args(c)?;
        }

        let mut git_args: Vec<String> = vec!["diff".to_string(), "--unified=3".to_string()];

        if let Some(c) = commit {
            git_args.push(c.to_string());
        }

        if cached {
            git_args.push("--cached".to_string());
        }

        git_args.push("--".to_string());
        git_args.push(files.to_string());

        let git_args_refs: Vec<&str> = git_args.iter().map(|s| s.as_str()).collect();
        let output = self.run_git_command(&git_args_refs, cwd).await?;

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
            output: serde_json::to_string_pretty(&result).unwrap_or_default(),
            error: None,
        })
    }

    async fn git_log(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
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
                cwd,
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
                .unwrap_or_default(),
            error: None,
        })
    }

    async fn git_branch(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let remote_branches = args
            .get("remote_branches")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let (output, parse_remote) = if remote_branches {
            (self.run_git_command(&["branch", "-r"], cwd).await, true)
        } else {
            (
                self.run_git_command(&["branch", "--format=%(refname:short)|%(HEAD)"], cwd)
                    .await,
                false,
            )
        };

        let output = output?;

        let mut branches = Vec::new();
        let mut current = String::new();

        for line in output.lines() {
            if parse_remote {
                let line = line.trim();
                if !line.is_empty() && !line.contains("->") {
                    branches.push(json!({
                        "name": line,
                        "current": false
                    }));
                }
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
            .unwrap_or_default(),
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
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let message = args
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'message' parameter"))?;

        // Sanitize commit message
        let sanitized = message
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        if sanitized.is_empty() {
            anyhow::bail!("Commit message cannot be empty");
        }

        // Limit message length
        let message = Self::truncate_commit_message(&sanitized);

        let output = self.run_git_command(&["commit", "-m", &message], cwd).await;

        match output {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: format!("Committed: {message}"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Commit failed: {e}")),
            }),
        }
    }

    async fn git_add(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let paths = args
            .get("paths")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'paths' parameter"))?;

        // Validate paths against injection patterns
        self.sanitize_git_args(paths)?;

        let output = self.run_git_command(&["add", "--", paths], cwd).await;

        match output {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: format!("Staged: {paths}"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Add failed: {e}")),
            }),
        }
    }

    async fn git_checkout(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let branch = args
            .get("branch")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'branch' parameter"))?;

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

        let create_branch = args
            .get("create_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let track = args.get("track").and_then(|v| v.as_bool()).unwrap_or(false);

        if track && create_branch && !branch_name.contains('/') {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(
                    "track=true requires a remote branch name (e.g., 'origin/main')".into(),
                ),
            });
        }

        let mut git_args = vec!["checkout"];

        if create_branch {
            git_args.push("-b");
            // For remote branches like "origin/feature", extract local name "feature"
            let local_name = if branch_name.contains('/') {
                branch_name.split('/').next_back().unwrap_or(branch_name)
            } else {
                branch_name
            };
            git_args.push(local_name);
            if track {
                git_args.push("--track");
            }
            git_args.push(branch_name);
        } else {
            git_args.push(branch_name);
        }

        let output = self.run_git_command(&git_args, cwd).await;

        match output {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: format!("Switched to branch: {branch_name}"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Checkout failed: {e}")),
            }),
        }
    }

    async fn git_stash(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("push");

        let output = match action {
            "push" | "save" => {
                self.run_git_command(&["stash", "push", "-m", "auto-stash"], cwd)
                    .await
            }
            "pop" => self.run_git_command(&["stash", "pop"], cwd).await,
            "list" => self.run_git_command(&["stash", "list"], cwd).await,
            "drop" => {
                let index_raw = args.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                let index = i32::try_from(index_raw)
                    .map_err(|_| anyhow::anyhow!("stash index too large: {index_raw}"))?;
                self.run_git_command(&["stash", "drop", &format!("stash@{{{index}}}")], cwd)
                    .await
            }
            _ => anyhow::bail!("Unknown stash action: {action}. Use: push, pop, list, drop"),
        };

        match output {
            Ok(out) => Ok(ToolResult {
                success: true,
                output: out,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Stash {action} failed: {e}")),
            }),
        }
    }

    async fn git_clone(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let url = match args.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'url' parameter".into()),
                });
            }
        };

        let sanitized_url = match self.sanitize_git_args(url) {
            Ok(u) => u.join(" "),
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Invalid URL: {e}")),
                });
            }
        };

        if !sanitized_url.starts_with("https://") && !sanitized_url.starts_with("http://") {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Only https:// and http:// URLs are allowed".into()),
            });
        }

        let destination = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                sanitized_url
                    .trim_end_matches('/')
                    .split('/')
                    .find(|s| !s.is_empty())
                    .unwrap_or("repo")
                    .trim_end_matches(".git")
            });

        if destination.starts_with('.') || destination.starts_with('~') {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("destination cannot start with '.' or '~'".into()),
            });
        }

        let target_dir = cwd.join(destination);
        if target_dir.exists() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Destination already exists: {destination}")),
            });
        }

        let output = self
            .run_git_command(&["clone", &sanitized_url, destination], cwd)
            .await;

        match output {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: format!(
                    "Cloned {} to {}/{}",
                    sanitized_url,
                    cwd.display(),
                    destination
                ),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Clone failed: {e}")),
            }),
        }
    }

    async fn git_pull(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let rebase = args
            .get("rebase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let remote = args.get("remote").and_then(|v| v.as_str());
        let branch = args.get("branch").and_then(|v| v.as_str());

        let mut git_args: Vec<String> = vec!["pull".to_string()];
        if rebase {
            git_args.push("--rebase".to_string());
        }

        if let Some(r) = remote {
            let sanitized = match self.sanitize_git_args(r) {
                Ok(s) if !s.is_empty() => s[0].clone(),
                _ => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("Invalid remote name".into()),
                    });
                }
            };
            git_args.push(sanitized);
        }
        if let Some(b) = branch {
            let sanitized = match self.sanitize_git_args(b) {
                Ok(s) if !s.is_empty() => s[0].clone(),
                _ => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("Invalid branch name".into()),
                    });
                }
            };
            git_args.push(sanitized);
        }

        let git_args_refs: Vec<&str> = git_args.iter().map(|s| s.as_str()).collect();
        let output = self.run_git_command(&git_args_refs, cwd).await;

        match output {
            Ok(out) => Ok(ToolResult {
                success: true,
                output: out,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Pull failed: {e}")),
            }),
        }
    }

    async fn git_fetch(
        &self,
        args: serde_json::Value,
        cwd: &std::path::Path,
    ) -> anyhow::Result<ToolResult> {
        let remote = args
            .get("remote")
            .and_then(|v| v.as_str())
            .unwrap_or("origin");
        let all = args.get("all").and_then(|v| v.as_bool()).unwrap_or(false);

        let sanitized_remote = match self.sanitize_git_args(remote) {
            Ok(r) if !r.is_empty() => r[0].clone(),
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Invalid remote name".into()),
                });
            }
        };

        let mut git_args: Vec<String> = vec!["fetch".to_string()];
        if all {
            git_args.push("--all".to_string());
        } else {
            git_args.push(sanitized_remote);
        }

        let git_args_refs: Vec<&str> = git_args.iter().map(|s| s.as_str()).collect();
        let output = self.run_git_command(&git_args_refs, cwd).await;

        match output {
            Ok(out) => Ok(ToolResult {
                success: true,
                output: out,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Fetch failed: {e}")),
            }),
        }
    }
}

#[async_trait]
impl Tool for GitOperationsTool {
    fn name(&self) -> &str {
        "git_operations"
    }

    fn description(&self) -> &str {
        "Perform structured Git operations (status, diff, log, branch, commit, add, checkout, stash, clone, pull, fetch). Use the 'cwd' parameter to target subdirectories within the workspace. Use 'commit' parameter for commit-based diffs (e.g., 'HEAD~3' or 'HEAD~3..HEAD'). For remote branches: run 'fetch' first to update remote refs, then use branch operation with remote_branches=true to list them. Use checkout with create_branch=true, track=true and branch='origin/branch-name' to switch to a remote branch. Provides parsed JSON output and integrates with security policy for autonomy controls."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["status", "diff", "log", "branch", "commit", "add", "checkout", "stash", "clone", "pull", "fetch"],
                    "description": "Git operation to perform"
                },
                "url": {
                    "type": "string",
                    "description": "Repository URL (for 'clone' operation)"
                },
                "destination": {
                    "type": "string",
                    "description": "Destination directory name (for 'clone' operation, defaults to repo name)"
                },
                "rebase": {
                    "type": "boolean",
                    "description": "Use rebase instead of merge (for 'pull' operation)"
                },
                "all": {
                    "type": "boolean",
                    "description": "Fetch all remotes (for 'fetch' operation)"
                },
                "message": {
                    "type": "string",
                    "description": "Commit message (for 'commit' operation)"
                },
                "paths": {
                    "type": "string",
                    "description": "File paths to stage (for 'add' operation)"
                },
                "branch": {
                    "type": "string",
                    "description": "Branch name (for 'checkout' and 'pull' operations). For remote branches, use 'origin/branch-name'"
                },
                "create_branch": {
                    "type": "boolean",
                    "description": "Create a new local branch (for 'checkout' operation)"
                },
                "track": {
                    "type": "boolean",
                    "description": "Set up upstream tracking for the new branch (for 'checkout' operation, use with create_branch)"
                },
                "remote_branches": {
                    "type": "boolean",
                    "description": "List remote-tracking branches (for 'branch' operation)"
                },
                "remote": {
                    "type": "string",
                    "description": "Remote name (for 'branch', 'pull' and 'fetch' operations, default: origin)"
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
                    "description": "Commit or commit range to diff (e.g., 'HEAD~3' or 'HEAD~3..HEAD') (for 'diff' operation)"
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
                "cwd": {
                    "type": "string",
                    "description": "Working directory for the operation (must be within workspace)"
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
                    output: String::new(),
                    error: Some("Missing 'operation' parameter".into()),
                });
            }
        };

        let effective_cwd = if let Some(cwd) = args.get("cwd").and_then(|v| v.as_str()) {
            let relative_path = self.workspace_dir.join(cwd);

            let canonical_workspace = std::fs::canonicalize(&self.workspace_dir)
                .unwrap_or_else(|_| self.workspace_dir.clone());
            let canonical_path =
                std::fs::canonicalize(&relative_path).unwrap_or_else(|_| relative_path.clone());

            if !canonical_path.starts_with(&canonical_workspace) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("cwd must be within workspace".into()),
                });
            }
            if !canonical_path.exists() {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("cwd does not exist: {cwd}")),
                });
            }
            canonical_path
        } else {
            self.workspace_dir.clone()
        };

        if operation != "clone" && !effective_cwd.join(".git").exists() {
            let mut current_dir = effective_cwd.as_path();
            let mut found_git = false;
            while current_dir.parent().is_some() {
                if current_dir.join(".git").exists() {
                    found_git = true;
                    break;
                }
                current_dir = current_dir.parent().unwrap();
            }

            if !found_git {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Not in a git repository".into()),
                });
            }
        }

        // Check autonomy level for write operations
        if self.requires_write_access(operation) {
            if !self.security.can_act() {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(
                        "Action blocked: git write operations require higher autonomy level".into(),
                    ),
                });
            }

            match self.security.autonomy {
                AutonomyLevel::ReadOnly => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
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
                output: String::new(),
                error: Some("Action blocked: rate limit exceeded".into()),
            });
        }

        // Execute the requested operation
        match operation {
            "status" => self.git_status(args, &effective_cwd).await,
            "diff" => self.git_diff(args, &effective_cwd).await,
            "log" => self.git_log(args, &effective_cwd).await,
            "branch" => self.git_branch(args, &effective_cwd).await,
            "commit" => self.git_commit(args, &effective_cwd).await,
            "add" => self.git_add(args, &effective_cwd).await,
            "checkout" => self.git_checkout(args, &effective_cwd).await,
            "stash" => self.git_stash(args, &effective_cwd).await,
            "clone" => self.git_clone(args, &effective_cwd).await,
            "pull" => self.git_pull(args, &effective_cwd).await,
            "fetch" => self.git_fetch(args, &effective_cwd).await,
            _ => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Unknown operation: {operation}")),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityPolicy;
    use tempfile::TempDir;

    fn test_tool(dir: &std::path::Path) -> GitOperationsTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
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

        assert!(!tool.requires_write_access("status"));
        assert!(!tool.requires_write_access("diff"));
        assert!(!tool.requires_write_access("log"));
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
    async fn branch_lists_remote_tracking() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        // Remote branches should return success even with no remotes
        let result = tool
            .execute(json!({"operation": "branch", "remote_branches": true}))
            .await
            .unwrap();
        assert!(result.success);
    }

    #[test]
    fn is_read_only_detection() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.is_read_only("status"));
        assert!(tool.is_read_only("diff"));
        assert!(tool.is_read_only("log"));
        assert!(tool.is_read_only("branch"));

        assert!(!tool.is_read_only("commit"));
        assert!(!tool.is_read_only("add"));
    }

    #[tokio::test]
    async fn blocks_readonly_mode_for_write_ops() {
        let tmp = TempDir::new().unwrap();
        // Initialize a git repository
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

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
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("higher autonomy"));
    }

    #[tokio::test]
    async fn allows_branch_listing_in_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        // Initialize a git repository so the command can succeed
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

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
            !error_msg.is_empty(),
            "Expected a git-related error message"
        );
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
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Missing 'operation'"));
    }

    #[tokio::test]
    async fn rejects_unknown_operation() {
        let tmp = TempDir::new().unwrap();
        // Initialize a git repository
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let result = tool.execute(json!({"operation": "push"})).await.unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Unknown operation"));
    }

    #[test]
    fn truncates_multibyte_commit_message_without_panicking() {
        let long = "🦀".repeat(2500);
        let truncated = GitOperationsTool::truncate_commit_message(&long);

        assert_eq!(truncated.chars().count(), 2000);
    }

    #[tokio::test]
    async fn cwd_rejects_path_outside_workspace() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "status", "cwd": "../outside"}))
            .await
            .unwrap();
        assert!(!result.success);
        let error = result.error.as_ref().unwrap();
        assert!(
            error.contains("cwd must be within workspace") || error.contains("cwd does not exist"),
            "Expected cwd rejection, got: {error}"
        );
    }

    #[tokio::test]
    async fn cwd_rejects_nonexistent_path() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "status", "cwd": "nonexistent_subdir"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("cwd does not exist"));
    }

    #[tokio::test]
    async fn cwd_uses_subdirectory_when_valid() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        std::fs::create_dir(tmp.path().join("subdir")).unwrap();

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({"operation": "status", "cwd": "subdir"}))
            .await
            .unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn clone_requires_write_access() {
        let tmp = TempDir::new().unwrap();
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool
            .execute(json!({"operation": "clone", "url": "https://github.com/example/repo.git"}))
            .await
            .unwrap();
        assert!(!result.success);
        let error = result.error.as_ref().unwrap();
        assert!(
            error.contains("read-only") || error.contains("higher autonomy"),
            "Expected autonomy error, got: {error}"
        );
    }

    #[tokio::test]
    async fn clone_rejects_parent_traversal() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "https://github.com/example/repo.git",
                "destination": "../outside"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("cannot start with"));
    }

    #[tokio::test]
    async fn clone_rejects_hidden_destination() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "https://github.com/example/repo.git",
                "destination": ".hidden"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("cannot start with"));
    }

    #[tokio::test]
    async fn clone_rejects_existing_destination() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("repo")).unwrap();

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "https://github.com/example/repo.git",
                "destination": "repo"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("already exists"));
    }

    #[tokio::test]
    async fn pull_requires_write_access() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool.execute(json!({"operation": "pull"})).await.unwrap();
        assert!(!result.success);
        let error = result.error.as_ref().unwrap();
        assert!(
            error.contains("read-only") || error.contains("higher autonomy"),
            "Expected autonomy error, got: {error}"
        );
    }

    #[tokio::test]
    async fn pull_succeeds_in_supervised_mode() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let result = tool.execute(json!({"operation": "pull"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Pull failed"));
    }

    #[test]
    fn clone_and_pull_are_write_operations() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(tool.requires_write_access("clone"));
        assert!(tool.requires_write_access("pull"));
    }

    #[test]
    fn fetch_is_read_only() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        assert!(!tool.requires_write_access("fetch"));
        assert!(tool.is_read_only("fetch"));
    }

    #[tokio::test]
    async fn fetch_succeeds_in_readonly_mode() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = GitOperationsTool::new(security, tmp.path().to_path_buf());

        let result = tool.execute(json!({"operation": "fetch"})).await.unwrap();
        let error = result.error.as_deref().unwrap_or("");
        assert!(
            result.success
                || error.contains("no remotes")
                || error.contains("not found")
                || error.contains("does not appear to be a git repository"),
            "Expected success or no-remotes error, got: {error}"
        );
    }

    #[tokio::test]
    async fn clone_rejects_invalid_url_scheme() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "git@github.com:user/repo.git"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("Only https:// and http:// URLs are allowed"));
    }

    #[tokio::test]
    async fn clone_rejects_injection_in_url() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "clone",
                "url": "https://github.com/user/repo.git; rm -rf /"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Invalid URL"));
    }

    #[tokio::test]
    async fn checkout_track_requires_remote_branch() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "checkout",
                "branch": "my-branch",
                "create_branch": true,
                "track": true
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("track=true requires a remote branch name"));
    }

    #[tokio::test]
    async fn checkout_allows_local_branch_with_track() {
        let tmp = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let tool = test_tool(tmp.path());

        let result = tool
            .execute(json!({
                "operation": "checkout",
                "branch": "feature",
                "create_branch": true,
                "track": false
            }))
            .await
            .unwrap();
        assert!(
            result.success
                || result
                    .error
                    .as_ref()
                    .map_or(false, |e| e.contains("failed"))
        );
    }

    #[tokio::test]
    async fn diff_accepts_commit_parameter() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({"operation": "diff", "commit": "HEAD"}))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn diff_accepts_commit_range() {
        let tmp = TempDir::new().unwrap();
        let tool = test_tool(tmp.path());
        let result = tool
            .execute(json!({"operation": "diff", "commit": "HEAD~1..HEAD"}))
            .await;
        assert!(result.is_ok());
    }
}
