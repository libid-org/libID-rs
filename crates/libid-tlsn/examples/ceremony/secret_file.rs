//! A new file only its owner can read, for a secret a tool writes once.
//!
//! Included by `#[path]` from `capture_ceremony` and from
//! `tests/secret_file.rs`; not an example of its own.

use std::{
    io::Write as _,
    path::Path,
};

/// Write `contents` to `path` as a new file with mode 0600.
///
/// `create_new` refuses an existing path, a directory and a symlink in the
/// same call that opens the file. If the write fails, the partial file is
/// removed. Unix only: the mode is what keeps the file private, so elsewhere
/// every path is refused.
pub fn write_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file =
        open_owner_only(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    written.map_err(|e| {
        let removed = match std::fs::remove_file(path) {
            Ok(()) => "it was removed".to_owned(),
            Err(e) => format!("delete it by hand, it may hold secrets ({e})"),
        };
        format!("writing {}: {e}; {removed}", path.display())
    })
}

#[cfg(unix)]
fn open_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_owner_only(_: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "a secret file is created with mode 0600, which only unix has",
    ))
}
