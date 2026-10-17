//! Filesystem walker that gathers classification candidates for the Python
//! sidecar.
//!
//! The walker is intentionally minimal — it produces a flat list of
//! [`FileCandidate`] entries with a small content preview (the first 4 KB
//! decoded UTF-8-lossy). Files that the path-guard would block anyway
//! (crypto containers) or that the sidecar cannot meaningfully classify
//! (pure binaries) are filtered out here to save Python latency.
//!
//! See spec §4.2 — "Pre-Filter: Crypto-Container werden gar nicht erst dem
//! Sidecar gegeben (sind eh hardcoded blockiert). Spart Latenz."

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Default per-file size cap (5 MB per spec §4.1).
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024;

/// Bytes of head-of-file we pass to the sidecar as `content_preview`
/// (spec §5.5 request schema). Raised from 4 KB → 16 KB so longer
/// CHANGELOG / README / journal-style files don't lose their PII signal
/// just because the personal name lives in line 50 instead of line 5.
pub const PREVIEW_BYTES: usize = 16 * 1024;

/// How many leading bytes we sniff for a NUL byte to decide "binary".
const BINARY_SNIFF_BYTES: usize = 1024;

/// Directories we never descend into during a classify-files walk. These
/// are universally noise (VCS metadata, virtualenvs, build artifacts).
const SKIP_DIR_NAMES: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".cache",
];

/// File extensions for crypto-containers we never bother classifying —
/// they're blocked unconditionally by the path-guard and have no useful
/// content preview. Lowercase, no leading dot.
const CRYPTO_EXTS: &[&str] = &[
    "kdbx",
    "kdb",
    "gpg",
    "pgp",
    "asc",
    "age",
    "p12",
    "pfx",
    "keychain-db",
];

/// One candidate file for classification — what we hand to the sidecar.
#[derive(Debug, Clone, PartialEq)]
pub struct FileCandidate {
    /// Absolute path to the file on disk.
    pub path: PathBuf,
    /// Last component of `path` as UTF-8 (lossy if invalid).
    pub filename: String,
    /// File size in bytes (from the metadata read during walk).
    pub size_bytes: u64,
    /// First [`PREVIEW_BYTES`] of the file decoded UTF-8-lossy.
    pub content_preview: String,
}

/// Tunables for the walker. Default via [`WalkOptions::default`].
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// `walkdir` max depth (None = unlimited). Spec: `--max-depth N`.
    pub max_depth: Option<usize>,
    /// Files strictly larger than this are skipped (default 5 MB).
    pub max_file_size_bytes: u64,
    /// Follow symbolic links during the walk (default false).
    pub follow_symlinks: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            follow_symlinks: false,
        }
    }
}

/// Walk `root` and return all classification candidates.
///
/// Skip rules (all enforced here, before the sidecar is ever called):
/// - any directory named in [`SKIP_DIR_NAMES`]
/// - hidden directories (`.foo`) — except the user-supplied `root` itself
/// - symlinks (unless `opts.follow_symlinks` is true)
/// - files larger than `opts.max_file_size_bytes`
/// - crypto-container extensions (path-guard would block them anyway)
/// - pure binary files (NUL byte in the first 1 KB)
///
/// IO errors on individual entries are silently skipped — we'd rather
/// produce a partial result than fail the whole walk for a single
/// unreadable file. The orchestrator (`classify_cmd.rs`) returns exit-4
/// when the *root* directory itself is unreadable.
pub fn walk_for_classification(root: &Path, opts: &WalkOptions) -> Vec<FileCandidate> {
    let mut out = Vec::new();
    let mut walker = WalkDir::new(root).follow_links(opts.follow_symlinks);
    if let Some(d) = opts.max_depth {
        walker = walker.max_depth(d);
    }

    let walker = walker.into_iter().filter_entry(|entry| {
        // Don't filter the root entry itself, even if it happens to start
        // with a dot (the user explicitly asked us to walk it).
        if entry.depth() == 0 {
            return true;
        }
        if entry.file_type().is_dir() {
            !is_skipped_dir(entry.file_name())
        } else {
            true
        }
    });

    for entry in walker.flatten() {
        if entry.depth() == 0 {
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if is_crypto_container(path) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size_bytes = meta.len();
        if size_bytes > opts.max_file_size_bytes {
            continue;
        }
        let preview = match read_preview(path) {
            Some(p) => p,
            None => continue, // binary or unreadable
        };

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        out.push(FileCandidate {
            path: path.to_path_buf(),
            filename,
            size_bytes,
            content_preview: preview,
        });
    }

    out
}

fn is_skipped_dir(name: &std::ffi::OsStr) -> bool {
    let s = name.to_string_lossy();
    if SKIP_DIR_NAMES.contains(&s.as_ref()) {
        return true;
    }
    // Any other hidden directory (".foo") is skipped — but only at
    // depth > 0; the root-depth check happens at the call site.
    s.starts_with('.')
}

fn is_crypto_container(path: &Path) -> bool {
    let Some(ext) = path.extension() else {
        return false;
    };
    let ext = ext.to_string_lossy().to_ascii_lowercase();
    CRYPTO_EXTS.contains(&ext.as_str())
}

/// Read up to [`PREVIEW_BYTES`] from `path`. Returns `None` if the file
/// is unreadable or detected as pure binary (NUL byte in the first
/// [`BINARY_SNIFF_BYTES`]).
fn read_preview(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0_u8; PREVIEW_BYTES];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);

    // Binary sniff: a NUL byte in the head means it's almost certainly
    // not text (zip-based office docs, images, executables). The Python
    // sidecar can't extract signal from a 4-KB binary slice anyway.
    let sniff_end = n.min(BINARY_SNIFF_BYTES);
    if buf[..sniff_end].contains(&0) {
        return None;
    }

    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn touch(path: &Path, body: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    #[test]
    fn empty_directory_returns_no_candidates() {
        let td = tempdir().unwrap();
        let out = walk_for_classification(td.path(), &WalkOptions::default());
        assert!(out.is_empty());
    }

    #[test]
    fn plain_text_file_is_included_with_preview() {
        let td = tempdir().unwrap();
        let p = td.path().join("note.txt");
        touch(&p, b"hello world\n");
        let out = walk_for_classification(td.path(), &WalkOptions::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].filename, "note.txt");
        assert_eq!(out[0].size_bytes, 12);
        assert!(out[0].content_preview.starts_with("hello world"));
    }

    #[test]
    fn skips_well_known_noise_dirs() {
        let td = tempdir().unwrap();
        // These should not appear in the result.
        touch(&td.path().join(".git/HEAD"), b"ref: refs/heads/main\n");
        touch(&td.path().join("node_modules/foo/index.js"), b"x\n");
        touch(&td.path().join("__pycache__/a.pyc"), b"py\n");
        touch(&td.path().join("target/debug/bin"), b"y\n");
        touch(&td.path().join(".venv/bin/python"), b"z\n");
        // This one should.
        touch(&td.path().join("keep.txt"), b"keep\n");

        let out = walk_for_classification(td.path(), &WalkOptions::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].filename, "keep.txt");
    }

    #[test]
    fn skips_hidden_subdirectory_but_walks_hidden_root() {
        let td = tempdir().unwrap();
        let hidden_root = td.path().join(".redacted-root");
        fs::create_dir_all(&hidden_root).unwrap();
        touch(&hidden_root.join("real.txt"), b"real\n");
        // a hidden subdir under the hidden root must still be skipped
        touch(&hidden_root.join(".inner/secret.txt"), b"shh\n");

        let out = walk_for_classification(&hidden_root, &WalkOptions::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].filename, "real.txt");
    }

    #[test]
    fn size_limit_cuts_off_large_files() {
        let td = tempdir().unwrap();
        let small = td.path().join("small.txt");
        let big = td.path().join("big.txt");
        touch(&small, &[b'a'; 100]);
        touch(&big, &vec![b'a'; 10_000]);

        let opts = WalkOptions {
            max_file_size_bytes: 1_000,
            ..WalkOptions::default()
        };
        let out = walk_for_classification(td.path(), &opts);
        let names: Vec<_> = out.iter().map(|c| c.filename.clone()).collect();
        assert_eq!(names, vec!["small.txt".to_string()]);
    }

    #[test]
    fn crypto_extensions_are_filtered() {
        let td = tempdir().unwrap();
        for name in [
            "vault.kdbx",
            "data.gpg",
            "msg.pgp",
            "sig.asc",
            "backup.age",
            "cert.p12",
            "cert.pfx",
            "login.keychain-db",
        ] {
            touch(&td.path().join(name), b"plain text content\n");
        }
        touch(&td.path().join("notes.md"), b"# notes\n");

        let out = walk_for_classification(td.path(), &WalkOptions::default());
        let names: Vec<_> = out.iter().map(|c| c.filename.clone()).collect();
        assert_eq!(names, vec!["notes.md".to_string()]);
    }

    #[test]
    fn binary_files_with_nul_byte_are_skipped() {
        let td = tempdir().unwrap();
        let mut binary = b"some text\x00more".to_vec();
        binary.extend(std::iter::repeat_n(0xff_u8, 50));
        touch(&td.path().join("blob.bin"), &binary);
        touch(&td.path().join("readme.md"), b"plain\n");

        let out = walk_for_classification(td.path(), &WalkOptions::default());
        let names: Vec<_> = out.iter().map(|c| c.filename.clone()).collect();
        assert_eq!(names, vec!["readme.md".to_string()]);
    }

    #[test]
    fn utf8_preview_is_returned_for_valid_text() {
        let td = tempdir().unwrap();
        let body = "Schöne Grüße aus München\n";
        touch(&td.path().join("greet.txt"), body.as_bytes());

        let out = walk_for_classification(td.path(), &WalkOptions::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].content_preview, body);
    }

    #[test]
    fn lossy_utf8_does_not_drop_the_file() {
        let td = tempdir().unwrap();
        // Latin-1 e-acute (0xE9) inside an otherwise ASCII file. Not a
        // NUL byte, so the binary sniff lets it through; from_utf8_lossy
        // replaces 0xE9 with U+FFFD.
        let mut body = b"caf".to_vec();
        body.push(0xE9);
        body.extend_from_slice(b" au lait\n");
        touch(&td.path().join("menu.txt"), &body);

        let out = walk_for_classification(td.path(), &WalkOptions::default());
        assert_eq!(out.len(), 1);
        assert!(out[0].content_preview.contains("caf"));
        assert!(out[0].content_preview.contains('\u{FFFD}'));
    }

    #[test]
    fn max_depth_zero_returns_nothing_below_root() {
        let td = tempdir().unwrap();
        touch(&td.path().join("a.txt"), b"a\n");
        touch(&td.path().join("sub/b.txt"), b"b\n");

        // depth=1 lets us see direct children only; depth=0 is the root entry itself.
        let opts = WalkOptions {
            max_depth: Some(1),
            ..WalkOptions::default()
        };
        let out = walk_for_classification(td.path(), &opts);
        let names: Vec<_> = out.iter().map(|c| c.filename.clone()).collect();
        assert_eq!(names, vec!["a.txt".to_string()]);
    }

    #[test]
    fn preview_is_capped_at_preview_bytes() {
        let td = tempdir().unwrap();
        // File large enough to exceed the preview cap (PREVIEW_BYTES + slack).
        let big = vec![b'x'; PREVIEW_BYTES * 2];
        touch(&td.path().join("big.txt"), &big);
        let out = walk_for_classification(td.path(), &WalkOptions::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].content_preview.len(), PREVIEW_BYTES);
        assert_eq!(out[0].size_bytes as usize, PREVIEW_BYTES * 2);
    }
}
