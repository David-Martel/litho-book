use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "litho-book")]
#[command(about = "A web-based reader for litho-generated documentation")]
#[command(version)]
pub struct Args {
    /// Path to the markdown documentation directory
    #[arg(short, long, value_name = "DIR")]
    pub docs_dir: PathBuf,

    /// Port to serve the web interface on
    #[arg(short, long, default_value = "3000", value_name = "PORT")]
    pub port: u16,

    /// Host to bind the server to
    #[arg(long, default_value = "127.0.0.1", value_name = "HOST")]
    pub host: String,

    /// Open browser automatically after starting the server
    #[arg(short, long)]
    pub open: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Enable hot reload - watch docs directory for changes
    #[arg(short, long)]
    pub watch: bool,

    /// Debounce interval for file watcher in milliseconds
    #[arg(long, default_value = "500", value_name = "MS")]
    pub watch_debounce: u64,

    /// Path to source code directory for AST analysis (optional)
    #[arg(short, long, value_name = "DIR")]
    pub source_dir: Option<PathBuf>,

    /// Path to workspace.toml for multi-project mode (optional)
    #[arg(long, value_name = "FILE")]
    pub workspace: Option<PathBuf>,

    /// Comma-separated list of languages for AST analysis (e.g., "rust,python,typescript")
    #[arg(long, value_name = "LANGS")]
    pub ast_languages: Option<String>,
}

impl Args {
    /// Validate the command line arguments
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.docs_dir.exists() {
            anyhow::bail!(
                "Documentation directory does not exist: {}",
                self.docs_dir.display()
            );
        }

        if !self.docs_dir.is_dir() {
            anyhow::bail!("Path is not a directory: {}", self.docs_dir.display());
        }

        // Check if port is available
        if self.port < 1024 && !is_privileged() {
            anyhow::bail!(
                "Port {} requires administrator privileges. Please use a port >= 1024 or run as administrator.",
                self.port
            );
        }

        Ok(())
    }

    /// Get the server URL
    pub fn server_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// Get the bind address
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Check if the current process has elevated privileges
fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    {
        // On Windows, we'll just return true for simplicity
        // In a real implementation, you'd check for admin privileges
        true
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a slice of CLI arguments into an Args struct.
    ///
    /// `docs_dir` is always prepended because it is a required argument; every
    /// test supplies `--docs-dir .` so clap does not error out on that field.
    fn parse(args: &[&str]) -> Args {
        // Build a full argv: binary name first, then the fixed docs-dir, then
        // whatever the individual test wants to exercise.
        let mut argv = vec!["litho-book", "--docs-dir", "."];
        argv.extend_from_slice(args);
        Args::try_parse_from(argv).expect("failed to parse args")
    }

    #[test]
    fn test_default_args() {
        let args = parse(&[]);
        assert!(!args.watch, "watch should default to false");
        assert_eq!(
            args.watch_debounce, 500,
            "watch_debounce should default to 500 ms"
        );
        assert!(
            args.source_dir.is_none(),
            "source_dir should default to None"
        );
        assert!(args.workspace.is_none(), "workspace should default to None");
        assert!(
            args.ast_languages.is_none(),
            "ast_languages should default to None"
        );
    }

    #[test]
    fn test_watch_flag() {
        let args = parse(&["--watch"]);
        assert!(args.watch, "--watch should set watch to true");
    }

    #[test]
    fn test_source_dir_flag() {
        let args = parse(&["--source-dir", "/tmp/src"]);
        assert_eq!(
            args.source_dir,
            Some(PathBuf::from("/tmp/src")),
            "--source-dir should set source_dir"
        );
    }

    #[test]
    fn test_workspace_flag() {
        let args = parse(&["--workspace", "/tmp/workspace.toml"]);
        assert_eq!(
            args.workspace,
            Some(PathBuf::from("/tmp/workspace.toml")),
            "--workspace should set workspace"
        );
    }

    #[test]
    fn test_watch_debounce_flag() {
        let args = parse(&["--watch-debounce", "1000"]);
        assert_eq!(
            args.watch_debounce, 1000,
            "--watch-debounce 1000 should set watch_debounce to 1000"
        );
    }

    #[test]
    fn test_ast_languages_flag() {
        let args = parse(&["--ast-languages", "rust,python,typescript"]);
        assert_eq!(
            args.ast_languages,
            Some("rust,python,typescript".to_string()),
            "--ast-languages should set ast_languages"
        );
    }
}
