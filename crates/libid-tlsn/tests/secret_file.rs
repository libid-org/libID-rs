//! The owner-only file `capture_ceremony` writes the identity-link witness to.

#![cfg(unix)]

#[path = "../examples/ceremony/secret_file.rs"]
mod secret_file;

use std::os::unix::fs::PermissionsExt as _;

#[test]
fn the_file_is_new_and_owner_only() {
    let dir =
        std::env::temp_dir().join(format!("libid-secret-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("w.secret.json");

    secret_file::write_new(&path, b"{}\n").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");

    // An existing path is refused and left as it was.
    assert!(secret_file::write_new(&path, b"other").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");

    std::fs::remove_dir_all(&dir).unwrap();
}
