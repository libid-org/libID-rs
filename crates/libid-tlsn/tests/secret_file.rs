//! The owner-only file `capture_ceremony` writes the identity-link witness to.

#![cfg(unix)]

#[path = "../examples/ceremony/secret_file.rs"]
mod secret_file;

use std::{
    os::unix::fs::{
        symlink,
        PermissionsExt as _,
    },
    path::PathBuf,
};

use secret_file::SecretFile;

/// A fresh directory for one test, removed when it ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let dir = std::env::temp_dir()
            .join(format!("libid-secret-file-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_file_is_owner_only_and_holds_what_was_written() {
    let scratch = Scratch::new("mode");
    let path = scratch.join("w.secret.json");
    let written = SecretFile::create(path.clone())
        .unwrap()
        .write(b"{}\n")
        .unwrap();
    assert_eq!(written, path);
    assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

#[test]
fn an_existing_path_is_refused_and_left_alone() {
    let scratch = Scratch::new("existing");
    let path = scratch.join("w.secret.json");
    std::fs::write(&path, b"keep").unwrap();
    let err = SecretFile::create(path.clone()).err().unwrap();
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
}

#[test]
fn a_symlink_is_refused_whether_or_not_its_target_exists() {
    let scratch = Scratch::new("symlink");
    let target = scratch.join("target");
    std::fs::write(&target, b"keep").unwrap();
    let link = scratch.join("w.secret.json");
    symlink(&target, &link).unwrap();
    let err = SecretFile::create(link).err().unwrap();
    assert!(err.contains("symlink"), "{err}");
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");

    let missing = scratch.join("missing");
    let dangling = scratch.join("d.secret.json");
    symlink(&missing, &dangling).unwrap();
    let err = SecretFile::create(dangling).err().unwrap();
    assert!(err.contains("symlink"), "{err}");
    assert!(!missing.exists(), "the link's target was created");
}

#[test]
fn a_directory_and_a_missing_parent_are_refused() {
    let scratch = Scratch::new("dirs");
    let dir = scratch.join("d.secret.json");
    std::fs::create_dir(&dir).unwrap();
    let err = SecretFile::create(dir).err().unwrap();
    assert!(err.contains("is a directory"), "{err}");

    let orphan = scratch.join("absent").join("w.secret.json");
    let err = SecretFile::create(orphan).err().unwrap();
    assert!(err.contains("does not exist; create it first"), "{err}");
}

#[test]
fn a_name_without_the_secret_suffix_is_refused_before_anything_is_created() {
    let scratch = Scratch::new("suffix");
    for name in ["witness.json", ".secret.json", "witness.secret.json.bak"] {
        let path = scratch.join(name);
        let err = SecretFile::create(path.clone()).err().unwrap();
        assert!(err.contains("must end in `.secret.json`"), "{name}: {err}");
        assert!(!path.exists(), "{name} was created");
    }
}

#[test]
fn an_unwritten_file_is_removed() {
    let scratch = Scratch::new("unwritten");
    let dropped = scratch.join("a.secret.json");
    drop(SecretFile::create(dropped.clone()).unwrap());
    assert!(!dropped.exists(), "dropping removes the file");

    let discarded = scratch.join("b.secret.json");
    let said = SecretFile::create(discarded.clone()).unwrap().discard();
    assert!(said.ends_with("was removed"), "{said}");
    assert!(!discarded.exists());
}
