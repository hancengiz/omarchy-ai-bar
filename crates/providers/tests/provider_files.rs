use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use nix::sys::stat::Mode;
use nix::unistd::{Gid, Uid, chown, geteuid, mkfifo};
use oab_providers::provider_files::{
    MAX_PROVIDER_FILE_BYTES, MAX_PROVIDER_SCAN_BYTES, MAX_PROVIDER_SCAN_DEPTH,
    MAX_PROVIDER_SCAN_ENTRIES, MAX_PROVIDER_SCAN_FILES, ProviderFileError, ProviderFileRoot,
    ProviderFileScanLimits,
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

struct Fixture {
    temporary: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            temporary: tempfile::tempdir().expect("temporary provider root"),
        }
    }

    fn path(&self) -> &Path {
        self.temporary.path()
    }

    fn directory(&self, relative: impl AsRef<Path>) -> PathBuf {
        let directory = self.path().join(relative);
        fs::create_dir_all(&directory).expect("fixture directory");
        directory
    }

    fn write(&self, relative: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("fixture parent directory");
        fs::write(&path, bytes).expect("fixture file");
        path
    }

    fn open(&self) -> ProviderFileRoot {
        ProviderFileRoot::open(self.path()).expect("opened provider root")
    }
}

fn limits(
    depth: usize,
    entries: usize,
    files: usize,
    file_bytes: usize,
    total_bytes: usize,
) -> ProviderFileScanLimits {
    ProviderFileScanLimits::new(depth, entries, files, file_bytes, total_bytes)
        .expect("valid fixture limits")
}

fn paths(candidates: &[oab_providers::provider_files::ProviderFileCandidate]) -> Vec<Vec<u8>> {
    candidates
        .iter()
        .map(|candidate| candidate.relative_path().as_os_str().as_bytes().to_vec())
        .collect()
}

#[test]
fn exact_read_is_bounded_and_zeroizing_result_is_redacted() {
    let fixture = Fixture::new();
    let secret = b"provider-secret-canary";
    fixture.write("auth.json", secret);
    let root = fixture.open();
    let cancellation = CancellationToken::new();

    let contents = root
        .read("auth.json", secret.len(), &cancellation)
        .expect("bounded exact read");
    assert_eq!(contents.as_bytes(), secret);
    assert_eq!(contents.len(), secret.len());
    assert!(!contents.is_empty());
    assert!(!format!("{root:?} {contents:?}").contains("provider-secret-canary"));
    assert!(!format!("{root:?}").contains(fixture.path().to_string_lossy().as_ref()));

    assert_eq!(
        root.read("auth.json", secret.len() - 1, &cancellation)
            .expect_err("oversized exact file"),
        ProviderFileError::TooLarge
    );
    let transferred = contents.into_bytes();
    assert_eq!(&*transferred, secret);
}

#[test]
fn empty_regular_files_are_valid_but_read_limits_must_be_positive() {
    let fixture = Fixture::new();
    fixture.write("empty.json", []);
    let root = fixture.open();
    let cancellation = CancellationToken::new();
    let contents = root
        .read("empty.json", 1, &cancellation)
        .expect("empty exact file");
    assert!(contents.is_empty());
    assert_eq!(
        root.read("empty.json", 0, &cancellation)
            .expect_err("zero read limit"),
        ProviderFileError::InvalidLimits
    );
    assert_eq!(
        root.read("empty.json", MAX_PROVIDER_FILE_BYTES + 1, &cancellation)
            .expect_err("excessive read limit"),
        ProviderFileError::InvalidLimits
    );
}

#[test]
fn invalid_and_missing_relative_paths_fail_without_path_diagnostics() {
    let fixture = Fixture::new();
    let root = fixture.open();
    let cancellation = CancellationToken::new();
    for path in ["", ".", "..", "a/../b", "a/./b", "a//b", "a/"] {
        let error = root
            .read(path, 128, &cancellation)
            .expect_err("invalid relative file path");
        assert_eq!(error, ProviderFileError::InvalidRelativePath, "{path:?}");
    }
    let canary_error = root
        .read("provider-path-canary/../secret", 128, &cancellation)
        .expect_err("redacted invalid path");
    assert!(!canary_error.to_string().contains("provider-path-canary"));
    assert_eq!(
        root.read("missing-secret-name", 128, &cancellation)
            .expect_err("missing provider file"),
        ProviderFileError::Missing
    );
    assert_eq!(
        root.read(fixture.path().join("absolute"), 128, &cancellation)
            .expect_err("absolute relative path"),
        ProviderFileError::InvalidRelativePath
    );
}

#[test]
fn root_rejects_relative_broad_dot_and_symlinked_paths() {
    let fixture = Fixture::new();
    let real = fixture.directory("real/root");
    let direct_link = fixture.path().join("root-link");
    symlink(&real, &direct_link).expect("fixture root symlink");
    let parent_link = fixture.path().join("parent-link");
    symlink(fixture.path().join("real"), &parent_link).expect("fixture parent symlink");

    assert_eq!(
        ProviderFileRoot::open("relative").expect_err("relative root"),
        ProviderFileError::InvalidRoot
    );
    assert_eq!(
        ProviderFileRoot::open("/").expect_err("broad root"),
        ProviderFileError::InvalidRoot
    );
    let dotted = fixture.path().join(".").join("real/root");
    assert_eq!(
        ProviderFileRoot::open(dotted).expect_err("dot syntax root"),
        ProviderFileError::InvalidRoot
    );
    assert_eq!(
        ProviderFileRoot::open(&direct_link).expect_err("symlink root"),
        ProviderFileError::UnsafeLayout
    );
    assert_eq!(
        ProviderFileRoot::open(parent_link.join("root")).expect_err("symlinked root ancestor"),
        ProviderFileError::UnsafeLayout
    );
}

#[test]
fn exact_read_rejects_intermediate_and_final_symlinks() {
    let fixture = Fixture::new();
    let outside = fixture.write("outside/secret", b"outside-canary");
    fixture.directory("inside");
    symlink(
        fixture.path().join("outside"),
        fixture.path().join("inside/link"),
    )
    .expect("intermediate symlink");
    symlink(&outside, fixture.path().join("final-link")).expect("final symlink");
    let root = fixture.open();
    let cancellation = CancellationToken::new();

    assert_eq!(
        root.read("inside/link/secret", 128, &cancellation)
            .expect_err("intermediate symlink"),
        ProviderFileError::UnsafeLayout
    );
    assert_eq!(
        root.read("final-link", 128, &cancellation)
            .expect_err("final symlink"),
        ProviderFileError::UnsafeLayout
    );
}

#[test]
fn fifos_sockets_and_hardlinks_are_rejected_without_blocking() {
    let fixture = Fixture::new();
    let fifo = fixture.path().join("credential-fifo");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("fixture FIFO");
    let socket = fixture.path().join("credential.sock");
    let _listener = UnixListener::bind(&socket).expect("fixture socket");
    let original = fixture.write("original", b"secret");
    fs::hard_link(&original, fixture.path().join("hardlink")).expect("fixture hard link");
    let root = fixture.open();
    let cancellation = CancellationToken::new();

    for path in ["credential-fifo", "credential.sock", "original", "hardlink"] {
        assert_eq!(
            root.read(path, 128, &cancellation)
                .expect_err("unsafe provider file type"),
            ProviderFileError::UnsafeLayout,
            "{path}"
        );
    }
    assert_eq!(
        root.scan("", ProviderFileScanLimits::default(), &cancellation)
            .expect_err("scan containing special file"),
        ProviderFileError::UnsafeLayout
    );
}

#[test]
fn recursive_scan_is_deterministic_over_raw_unix_names() {
    let fixture = Fixture::new();
    fixture.write("z.json", b"z");
    fixture.write("a/z.json", b"az");
    fixture.write("a/a.json", b"aa");
    let raw_name = OsString::from_vec(vec![b'b', b'/', 0x80, b'.', b'j']);
    fixture.write(PathBuf::from(&raw_name), b"raw");
    let root = fixture.open();
    let cancellation = CancellationToken::new();
    let scan_limits = limits(2, 16, 16, 16, 64);

    let first = root
        .scan("", scan_limits, &cancellation)
        .expect("first deterministic scan");
    let second = root
        .scan("", scan_limits, &cancellation)
        .expect("second deterministic scan");
    let expected = vec![
        b"a/a.json".to_vec(),
        b"a/z.json".to_vec(),
        vec![b'b', b'/', 0x80, b'.', b'j'],
        b"z.json".to_vec(),
    ];
    assert_eq!(paths(&first), expected);
    assert_eq!(paths(&second), expected);
}

#[test]
fn scan_relative_directory_keeps_root_relative_candidate_paths() {
    let fixture = Fixture::new();
    fixture.write("sessions/account/one.jsonl", b"one");
    fixture.write("unrelated", b"ignored-by-subroot");
    let root = fixture.open();
    let candidates = root
        .scan(
            "sessions",
            limits(2, 8, 8, 64, 128),
            &CancellationToken::new(),
        )
        .expect("subroot scan");
    assert_eq!(paths(&candidates), [b"sessions/account/one.jsonl".to_vec()]);
}

#[test]
fn scan_enforces_depth_entry_file_and_byte_budgets() {
    let depth_fixture = Fixture::new();
    depth_fixture.write("nested/file", b"x");
    assert_eq!(
        depth_fixture
            .open()
            .scan("", limits(0, 8, 8, 8, 8), &CancellationToken::new())
            .expect_err("depth limit"),
        ProviderFileError::TooDeep
    );

    let count_fixture = Fixture::new();
    count_fixture.write("a", b"a");
    count_fixture.write("b", b"b");
    count_fixture.write("c", b"c");
    let root = count_fixture.open();
    assert_eq!(
        root.scan("", limits(0, 2, 2, 8, 16), &CancellationToken::new())
            .expect_err("entry limit"),
        ProviderFileError::TooManyEntries
    );
    assert_eq!(
        root.scan("", limits(0, 8, 2, 8, 16), &CancellationToken::new())
            .expect_err("file limit"),
        ProviderFileError::TooManyEntries
    );

    let byte_fixture = Fixture::new();
    byte_fixture.write("a", b"123");
    byte_fixture.write("b", b"456");
    let root = byte_fixture.open();
    assert_eq!(
        root.scan("", limits(0, 8, 8, 2, 8), &CancellationToken::new())
            .expect_err("per-file byte limit"),
        ProviderFileError::TooLarge
    );
    assert_eq!(
        root.scan("", limits(0, 8, 8, 4, 5), &CancellationToken::new())
            .expect_err("aggregate byte limit"),
        ProviderFileError::TooLarge
    );
}

#[test]
fn scan_limit_constructor_rejects_unbounded_values() {
    let excessive = [
        ProviderFileScanLimits::new(MAX_PROVIDER_SCAN_DEPTH + 1, 1, 1, 1, 1),
        ProviderFileScanLimits::new(0, MAX_PROVIDER_SCAN_ENTRIES + 1, 1, 1, 1),
        ProviderFileScanLimits::new(0, 1, MAX_PROVIDER_SCAN_FILES + 1, 1, 1),
        ProviderFileScanLimits::new(
            0,
            1,
            1,
            MAX_PROVIDER_FILE_BYTES + 1,
            MAX_PROVIDER_SCAN_BYTES,
        ),
        ProviderFileScanLimits::new(0, 1, 1, 1, MAX_PROVIDER_SCAN_BYTES + 1),
        ProviderFileScanLimits::new(0, 0, 1, 1, 1),
        ProviderFileScanLimits::new(0, 1, 0, 1, 1),
        ProviderFileScanLimits::new(0, 1, 1, 0, 1),
        ProviderFileScanLimits::new(0, 1, 1, 2, 1),
    ];
    for result in excessive {
        assert_eq!(
            result.expect_err("invalid scan limits"),
            ProviderFileError::InvalidLimits
        );
    }
}

#[test]
fn candidates_are_root_scoped_identity_pinned_and_redacted() {
    let first_fixture = Fixture::new();
    first_fixture.write("account-secret-name", b"first-secret-canary");
    let first = first_fixture.open();
    let candidates = first
        .scan("", limits(0, 4, 4, 64, 64), &CancellationToken::new())
        .expect("candidate scan");
    let candidate = candidates.first().expect("candidate");
    assert_eq!(candidate.len(), b"first-secret-canary".len());
    assert!(!candidate.is_empty());
    assert!(!format!("{candidate:?}").contains("account-secret-name"));
    let contents = first
        .read_candidate(candidate, &CancellationToken::new())
        .expect("identity-pinned read");
    assert_eq!(contents.as_bytes(), b"first-secret-canary");

    let second_fixture = Fixture::new();
    let second = second_fixture.open();
    assert_eq!(
        second
            .read_candidate(candidate, &CancellationToken::new())
            .expect_err("cross-root candidate"),
        ProviderFileError::WrongRoot
    );

    first_fixture.write("account-secret-name", b"changed-secret-value");
    assert_eq!(
        first
            .read_candidate(candidate, &CancellationToken::new())
            .expect_err("changed candidate"),
        ProviderFileError::Changed
    );
}

#[test]
fn candidate_lines_are_streamed_and_oversized_records_are_skipped() {
    let fixture = Fixture::new();
    fixture.write(
        "events.jsonl",
        b"one\nrecord-too-large\ntwo-without-newline",
    );
    let root = fixture.open();
    let candidates = root
        .scan("", limits(0, 2, 2, 64, 64), &CancellationToken::new())
        .expect("candidate scan");
    let mut lines = Vec::new();
    root.visit_candidate_lines(&candidates[0], 8, &CancellationToken::new(), |line| {
        lines.push(line.to_vec());
    })
    .expect("bounded line stream");

    assert_eq!(lines, [b"one".to_vec()]);
    assert_eq!(
        root.visit_candidate_lines(&candidates[0], 0, &CancellationToken::new(), |_| {})
            .expect_err("zero line limit"),
        ProviderFileError::InvalidLimits
    );
}

#[test]
fn replaced_candidate_never_reads_a_symlink_target() {
    let fixture = Fixture::new();
    let selected = fixture.write("selected", b"inside");
    let outside = fixture.write("outside", b"outside-secret-canary");
    let root = fixture.open();
    let candidates = root
        .scan("", limits(0, 4, 4, 64, 128), &CancellationToken::new())
        .expect("candidate scan");
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.relative_path() == Path::new("selected"))
        .expect("selected candidate");
    fs::remove_file(selected).expect("remove selected fixture");
    symlink(outside, fixture.path().join("selected")).expect("replace with symlink");

    assert_eq!(
        root.read_candidate(candidate, &CancellationToken::new())
            .expect_err("symlink replacement"),
        ProviderFileError::Changed
    );
}

#[test]
fn cancelled_reads_and_scans_return_no_partial_result() {
    let fixture = Fixture::new();
    fixture.write("auth.json", vec![b'x'; 64 * 1024]);
    let root = fixture.open();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        root.read("auth.json", 64 * 1024, &cancellation)
            .expect_err("cancelled read"),
        ProviderFileError::Cancelled
    );
    assert_eq!(
        root.scan("", ProviderFileScanLimits::default(), &cancellation)
            .expect_err("cancelled scan"),
        ProviderFileError::Cancelled
    );
}

#[test]
fn provider_root_must_belong_to_current_effective_user() {
    let fixture = Fixture::new();
    if geteuid().is_root() {
        let nobody = Uid::from_raw(65_534);
        chown(fixture.path(), Some(nobody), Some(Gid::from_raw(65_534)))
            .expect("change fixture owner");
        assert_eq!(
            ProviderFileRoot::open(fixture.path()).expect_err("foreign-owned root"),
            ProviderFileError::WrongOwner
        );
        chown(fixture.path(), Some(geteuid()), Some(Gid::from_raw(0)))
            .expect("restore fixture owner");
    } else {
        assert_eq!(
            ProviderFileRoot::open("/tmp").expect_err("system-owned root"),
            ProviderFileError::WrongOwner
        );
    }
}

#[test]
fn scan_rejects_symlinks_even_when_the_target_is_inside_the_root() {
    let fixture = Fixture::new();
    fixture.write("real", b"secret");
    symlink("real", fixture.path().join("alias")).expect("fixture relative symlink");
    assert_eq!(
        fixture
            .open()
            .scan(
                "",
                ProviderFileScanLimits::default(),
                &CancellationToken::new()
            )
            .expect_err("symlink in scan"),
        ProviderFileError::UnsafeLayout
    );
}

#[test]
fn scan_accepts_the_exact_count_and_byte_boundaries() {
    let fixture = Fixture::new();
    fixture.write("a", b"123");
    fixture.write("b", b"456");
    let root = fixture.open();
    let candidates = root
        .scan("", limits(0, 2, 2, 3, 6), &CancellationToken::new())
        .expect("exact scan boundaries");
    assert_eq!(paths(&candidates), [b"a".to_vec(), b"b".to_vec()]);
}

#[test]
fn non_utf8_file_names_are_not_lossily_collapsed() {
    let fixture = Fixture::new();
    let first = OsString::from_vec(vec![0x80]);
    let second = OsString::from_vec(vec![0x81]);
    fixture.write(PathBuf::from(&second), b"second");
    fixture.write(PathBuf::from(&first), b"first");
    let candidates = fixture
        .open()
        .scan(
            OsStr::new(""),
            limits(0, 2, 2, 16, 16),
            &CancellationToken::new(),
        )
        .expect("raw-name scan");
    assert_eq!(paths(&candidates), [vec![0x80], vec![0x81]]);
}
