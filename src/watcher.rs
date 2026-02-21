//! File-system watcher for live-reload support.
//!
//! This module wraps the `notify` crate to produce a typed, debounced stream of
//! [`WatchEvent`]s over a [`tokio::sync::broadcast`] channel.  Consumers can
//! subscribe to the channel and react to documentation or source-code changes
//! without any knowledge of the underlying OS primitives.
//!
//! # Example
//!
//! ```no_run
//! use litho_book::watcher::{WatcherConfig, WatchEvent, start_watcher};
//! use std::path::PathBuf;
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let config = WatcherConfig {
//!     docs_dir: PathBuf::from("./docs"),
//!     source_dir: None,
//!     debounce_ms: 200,
//! };
//! let (tx, mut rx) = start_watcher(config)?;
//! tokio::spawn(async move {
//!     while let Ok(event) = rx.recv().await {
//!         println!("Watch event: {:?}", event);
//!     }
//! });
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Events produced by the watcher after classification and debouncing.
#[derive(Debug, Clone)]
#[allow(dead_code)] // variants consumed by downstream pipeline phases
pub enum WatchEvent {
    /// A Markdown document was created or modified inside the watched docs dir.
    DocChanged(PathBuf),
    /// A Markdown document was deleted from the watched docs dir.
    DocDeleted(PathBuf),
    /// A source file (outside the docs dir) was created or modified.
    SourceChanged(PathBuf),
    /// The document tree was rebuilt after a batch of [`WatchEvent::DocChanged`]
    /// or [`WatchEvent::DocDeleted`] events.
    TreeRebuilt,
}

/// Configuration for [`start_watcher`].
#[derive(Debug, Clone)]
#[allow(dead_code)] // consumed by downstream pipeline phases
pub struct WatcherConfig {
    /// Directory containing the Markdown documentation to watch.
    pub docs_dir: PathBuf,
    /// Optional directory containing source files to watch (e.g. a Rust `src/`
    /// tree).  Files outside both directories are silently ignored.
    pub source_dir: Option<PathBuf>,
    /// How long to wait (in milliseconds) after the first filesystem event
    /// before flushing the batch.  Events that arrive within the window are
    /// coalesced.
    pub debounce_ms: u64,
}

// ---------------------------------------------------------------------------
// classify_event
// ---------------------------------------------------------------------------

/// Classify a raw `notify` [`Event`] into zero or more [`WatchEvent`]s.
///
/// Each path in `event.paths` is evaluated independently:
///
/// * Paths inside `docs_dir` with a `.md` extension produce [`WatchEvent::DocChanged`]
///   or [`WatchEvent::DocDeleted`] depending on the event kind.
/// * Paths inside `source_dir` (when provided) that are created or modified
///   produce [`WatchEvent::SourceChanged`].
/// * All other paths (non-`.md` files in docs_dir, files outside both dirs,
///   etc.) are silently ignored.
///
/// # Examples
///
/// ```
/// use notify::{Event, EventKind};
/// use notify::event::CreateKind;
/// use litho_book::watcher::{classify_event, WatchEvent};
/// use std::path::{Path, PathBuf};
///
/// let docs = Path::new("/docs");
/// let event = Event {
///     kind: EventKind::Create(CreateKind::File),
///     paths: vec![PathBuf::from("/docs/guide.md")],
///     attrs: Default::default(),
/// };
/// let events = classify_event(&event, docs, None);
/// assert!(matches!(events[0], WatchEvent::DocChanged(_)));
/// ```
#[allow(dead_code)] // used in tests and by downstream pipeline phases
pub fn classify_event(
    event: &Event,
    docs_dir: &Path,
    source_dir: Option<&Path>,
) -> Vec<WatchEvent> {
    let mut out = Vec::new();

    for path in &event.paths {
        let is_in_docs = path.starts_with(docs_dir);
        let is_in_source = source_dir.is_some_and(|src| path.starts_with(src));
        let is_md = path.extension().and_then(|e| e.to_str()) == Some("md");

        if is_in_docs && is_md {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    out.push(WatchEvent::DocChanged(path.clone()));
                }
                EventKind::Remove(_) => {
                    out.push(WatchEvent::DocDeleted(path.clone()));
                }
                _ => {}
            }
        } else if is_in_source {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    out.push(WatchEvent::SourceChanged(path.clone()));
                }
                _ => {}
            }
        }
        // Files outside both dirs, or non-.md files in docs_dir, are ignored.
    }

    out
}

// ---------------------------------------------------------------------------
// start_watcher
// ---------------------------------------------------------------------------

/// Start a background watcher task and return the broadcast sender and task handle.
///
/// The returned [`broadcast::Sender`] can be used to create additional
/// [`broadcast::Receiver`]s via [`broadcast::Sender::subscribe`].  The
/// [`tokio::task::JoinHandle`] represents the background blocking task; it
/// runs until the docs directory becomes unwatchable or the process exits.
///
/// # Errors
///
/// Returns an error if `notify` cannot set up watches on either directory.
#[allow(dead_code)] // consumed by downstream pipeline phases
pub fn start_watcher(
    config: WatcherConfig,
) -> anyhow::Result<(broadcast::Sender<WatchEvent>, tokio::task::JoinHandle<()>)> {
    let (broadcast_tx, _rx) = broadcast::channel::<WatchEvent>(256);
    let tx_clone = broadcast_tx.clone();

    let docs_dir = config.docs_dir.clone();
    let source_dir = config.source_dir.clone();
    let debounce_ms = config.debounce_ms;

    // Channel between the notify callback and our blocking loop.
    let (notify_tx, notify_rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = notify::recommended_watcher(notify_tx)
        .map_err(|e| anyhow::anyhow!("Failed to create file watcher: {}", e))?;

    watcher
        .watch(&docs_dir, RecursiveMode::Recursive)
        .map_err(|e| anyhow::anyhow!("Failed to watch docs dir {}: {}", docs_dir.display(), e))?;

    if let Some(ref src) = source_dir {
        watcher
            .watch(src, RecursiveMode::Recursive)
            .map_err(|e| anyhow::anyhow!("Failed to watch source dir {}: {}", src.display(), e))?;
    }

    let handle = tokio::task::spawn_blocking(move || {
        // Keep `watcher` alive for the duration of the blocking task.
        let _watcher = watcher;
        let debounce = Duration::from_millis(debounce_ms);

        loop {
            // Wait for the first event.
            let first = match notify_rx.recv() {
                Ok(r) => r,
                Err(_) => {
                    debug!("Watcher notify channel closed, exiting");
                    break;
                }
            };

            // Collect the initial result.
            let mut raw_events: Vec<Event> = Vec::new();
            match first {
                Ok(ev) => raw_events.push(ev),
                Err(e) => {
                    warn!("Watcher error: {}", e);
                }
            }

            // Drain additional events that arrive within the debounce window.
            let deadline = std::time::Instant::now() + debounce;
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match notify_rx.recv_timeout(remaining) {
                    Ok(Ok(ev)) => raw_events.push(ev),
                    Ok(Err(e)) => warn!("Watcher error during debounce: {}", e),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        debug!("Watcher notify channel disconnected during debounce");
                        return;
                    }
                }
            }

            // Classify and broadcast the collected events.
            let source_ref = source_dir.as_deref();
            let mut had_doc_change = false;

            for ev in &raw_events {
                let classified = classify_event(ev, &docs_dir, source_ref);
                for watch_event in classified {
                    if matches!(
                        watch_event,
                        WatchEvent::DocChanged(_) | WatchEvent::DocDeleted(_)
                    ) {
                        had_doc_change = true;
                    }
                    if let Err(e) = tx_clone.send(watch_event) {
                        // No active receivers — not an error worth logging at warn.
                        debug!("No broadcast receivers: {}", e);
                    }
                }
            }

            // After any doc change batch, signal that the tree should be rebuilt.
            if had_doc_change && let Err(e) = tx_clone.send(WatchEvent::TreeRebuilt) {
                debug!("No broadcast receivers for TreeRebuilt: {}", e);
            }
        }

        error!("Watcher loop exited unexpectedly");
    });

    Ok((broadcast_tx, handle))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use notify::EventKind;
    use notify::event::{CreateKind, DataChange, ModifyKind, RemoveKind};

    fn make_event(kind: EventKind, paths: Vec<PathBuf>) -> Event {
        Event {
            kind,
            paths,
            attrs: Default::default(),
        }
    }

    #[test]
    fn test_classify_doc_created() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/docs/guide.md")],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], WatchEvent::DocChanged(p) if p == &PathBuf::from("/docs/guide.md"))
        );
    }

    #[test]
    fn test_classify_doc_modified() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            vec![PathBuf::from("/docs/readme.md")],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], WatchEvent::DocChanged(p) if p == &PathBuf::from("/docs/readme.md"))
        );
    }

    #[test]
    fn test_classify_doc_deleted() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Remove(RemoveKind::File),
            vec![PathBuf::from("/docs/old.md")],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], WatchEvent::DocDeleted(p) if p == &PathBuf::from("/docs/old.md"))
        );
    }

    #[test]
    fn test_classify_non_md_ignored() {
        let docs = PathBuf::from("/docs");
        // A .txt file inside docs_dir should produce no events.
        let event = make_event(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            vec![PathBuf::from("/docs/notes.txt")],
        );
        let result = classify_event(&event, &docs, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_classify_source_changed() {
        let docs = PathBuf::from("/docs");
        let src = PathBuf::from("/src");
        let event = make_event(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            vec![PathBuf::from("/src/lib.rs")],
        );
        let result = classify_event(&event, &docs, Some(&src));
        assert_eq!(result.len(), 1);
        assert!(
            matches!(&result[0], WatchEvent::SourceChanged(p) if p == &PathBuf::from("/src/lib.rs"))
        );
    }

    #[test]
    fn test_classify_outside_both_dirs_ignored() {
        let docs = PathBuf::from("/docs");
        let src = PathBuf::from("/src");
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/tmp/random.md")],
        );
        let result = classify_event(&event, &docs, Some(&src));
        assert!(result.is_empty());
    }

    #[test]
    fn test_classify_multiple_paths() {
        let docs = PathBuf::from("/docs");
        let src = PathBuf::from("/src");
        // One path in docs (.md), one in src, one ignored.
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![
                PathBuf::from("/docs/new.md"),
                PathBuf::from("/src/server.rs"),
                PathBuf::from("/other/file.md"),
            ],
        );
        let result = classify_event(&event, &docs, Some(&src));
        assert_eq!(result.len(), 2);
        assert!(
            matches!(&result[0], WatchEvent::DocChanged(p) if p == &PathBuf::from("/docs/new.md"))
        );
        assert!(
            matches!(&result[1], WatchEvent::SourceChanged(p) if p == &PathBuf::from("/src/server.rs"))
        );
    }
}
