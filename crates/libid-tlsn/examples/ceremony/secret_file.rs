//! A new file only its owner can read, for a secret a tool writes once.
//!
//! Included by `#[path]` from `capture_ceremony` and from
//! `tests/secret_file.rs`; not an example of its own. Unix only: the mode is
//! what keeps the file private.

#![allow(dead_code)]

use std::{
    fs::{
        File,
        OpenOptions,
    },
    io::{
        ErrorKind,
        Write as _,
    },
    os::unix::fs::OpenOptionsExt as _,
    path::{
        Path,
        PathBuf,
    },
};

/// The suffix a secret file's name ends in: what the `*.secret.json`
/// `.gitignore` rules match, and what tells a reader the file is secret.
pub const SECRET_SUFFIX: &str = ".secret.json";

/// A file created new with mode 0600, and removed again unless
/// [`SecretFile::write`] completes.
///
/// Creating it is the check: `create_new` refuses an existing path, a
/// directory and a symlink (dangling or not) in the same call that opens the
/// file, so nothing can be swapped in between a check and the open.
pub struct SecretFile {
    path: PathBuf,
    file: Option<File>,
    /// Whether dropping this removes the file.
    armed: bool,
}

impl SecretFile {
    /// Create `path`, whose name must end in [`SECRET_SUFFIX`], as a new
    /// owner-only file. An error names what is wrong and the fix.
    pub fn create(path: PathBuf) -> Result<Self, String> {
        let named = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.len() > SECRET_SUFFIX.len() && name.ends_with(SECRET_SUFFIX)
            });
        if !named {
            return Err(format!(
                "{}: the name must end in `{SECRET_SUFFIX}`, so .gitignore rules and readers \
                 recognise the file as secret",
                path.display()
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| refusal(&path, e))?;
        Ok(Self {
            path,
            file: Some(file),
            armed: true,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `contents` and keep the file. If the write fails, the partial
    /// file is removed and the error says so, or says to delete it by hand.
    pub fn write(mut self, contents: &[u8]) -> Result<PathBuf, String> {
        let mut file = self.file.take().expect("a SecretFile is written once");
        let written = file.write_all(contents).and_then(|()| file.sync_all());
        drop(file);
        match written {
            Ok(()) => {
                self.armed = false;
                Ok(self.path.clone())
            }
            Err(e) => {
                let removed = self.remove();
                Err(format!("writing {}: {e}. {removed}", self.path.display()))
            }
        }
    }

    /// Remove the file unwritten. Returns a sentence saying whether it is
    /// gone.
    pub fn discard(mut self) -> String {
        self.remove()
    }

    fn remove(&mut self) -> String {
        self.file = None;
        self.armed = false;
        match std::fs::remove_file(&self.path) {
            Ok(()) => format!("{} was removed", self.path.display()),
            Err(e) => format!(
                "{} could not be removed ({e}); delete it by hand, it may hold secrets",
                self.path.display()
            ),
        }
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        if self.armed {
            self.file = None;
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Why `path` could not be created new, and what to do about it.
fn refusal(path: &Path, e: std::io::Error) -> String {
    let shown = path.display();
    match e.kind() {
        ErrorKind::AlreadyExists => match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => {
                format!("{shown} is a directory; name a new file inside it")
            }
            Ok(meta) if meta.file_type().is_symlink() => format!(
                "{shown} is a symlink; a secret file is never written through one. Name a \
                 path that does not exist"
            ),
            _ => format!(
                "{shown} already exists; a secret file is only ever created new. Remove it, or \
                 name a path that does not exist"
            ),
        },
        ErrorKind::NotFound => format!(
            "{shown}: the directory {} does not exist; create it first",
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .display()
        ),
        _ => format!("{shown}: {e}"),
    }
}
