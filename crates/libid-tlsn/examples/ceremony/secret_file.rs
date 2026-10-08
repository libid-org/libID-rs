//! A new file only its owner can read, for a secret a tool writes once.
//!
//! Included by `#[path]` from `capture_ceremony` and from
//! `tests/secret_file.rs`; not an example of its own. Unix only: the mode is
//! what keeps the file private, so elsewhere [`SecretFile::create`] refuses
//! every path.
//!
//! A path inside a git work tree is accepted only where that tree's ignore
//! rules match it. This repository ignores `*.secret.json`; libID-contracts
//! and libID-circuits do not, so a witness named for this repository's rule
//! is still refused inside either of them.

#![allow(dead_code)]

use std::{
    ffi::OsStr,
    fs::File,
    io::{
        ErrorKind,
        Write as _,
    },
    path::{
        Path,
        PathBuf,
    },
    process::Command,
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
    /// owner-only file. Inside a git work tree, the tree's ignore rules must
    /// match it. An error names what is wrong and the fix, and nothing is
    /// created.
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
        refuse_unignored(&path)?;
        let file = open_owner_only(&path).map_err(|e| refusal(&path, e))?;
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

/// `path` opened new, mode 0600, never through a symlink.
#[cfg(unix)]
fn open_owner_only(path: &Path) -> std::io::Result<File> {
    use std::{
        fs::OpenOptions,
        os::unix::fs::OpenOptionsExt as _,
    };
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// No mode to make the file owner-only with, so no file.
#[cfg(not(unix))]
fn open_owner_only(_: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "a secret file is created with mode 0600, which only unix has; run this on Linux or macOS",
    ))
}

/// `git` run in `dir`, or a refusal saying git is needed.
fn git(dir: &Path, args: &[&OsStr]) -> Result<std::process::Output, String> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| {
            format!(
                "running git in {}: {e}. A secret file is written only where git can say it \
                 will not be committed; install git",
                dir.display()
            )
        })
}

/// Refuse `path` if it lies in a git work tree whose ignore rules do not
/// match it.
///
/// Outside every work tree (`rev-parse --is-inside-work-tree` fails or does
/// not print `true`) the path is accepted. Inside one, only `check-ignore`
/// exiting 0 accepts it; exit 1 (not ignored, or tracked), any other git
/// failure, and git being absent all refuse.
fn refuse_unignored(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(format!(
            "{}: the directory {} does not exist; create it first",
            path.display(),
            parent.display()
        ));
    }
    let inside = git(
        parent,
        &["rev-parse".as_ref(), "--is-inside-work-tree".as_ref()],
    )?;
    if !inside.status.success() || inside.stdout.trim_ascii() != b"true" {
        return Ok(());
    }
    let name = path
        .file_name()
        .expect("the suffix check found a file name");
    let ignored = git(
        parent,
        &["check-ignore".as_ref(), "-q".as_ref(), "--".as_ref(), name],
    )?;
    match ignored.status.code() {
        Some(0) => Ok(()),
        Some(1) => {
            let top = git(parent, &["rev-parse".as_ref(), "--show-toplevel".as_ref()])
                .map(|out| String::from_utf8_lossy(out.stdout.trim_ascii()).into_owned())
                .unwrap_or_default();
            Err(format!(
                "{} is in the git work tree {top} and not ignored by it, so it could be \
                 committed. Name a path outside every git work tree, such as one in the system \
                 temporary directory",
                path.display()
            ))
        }
        _ => Err(format!(
            "{}: git check-ignore failed ({}: {}), so whether the path could be committed is \
             unknown. Name a path outside every git work tree",
            path.display(),
            ignored.status,
            String::from_utf8_lossy(ignored.stderr.trim_ascii())
        )),
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
