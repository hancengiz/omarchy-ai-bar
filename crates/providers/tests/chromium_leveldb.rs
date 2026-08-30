use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use oab_providers::browser_profile::{
    BrowserKind, BrowserProfile, BrowserProfileDiscovery, BrowserProfileRoots,
};
use oab_providers::chromium_leveldb::{
    ChromiumHttpsOrigin, ChromiumLevelDbError, ChromiumLevelDbReader,
};

const LOG_BLOCK_BYTES: usize = 32 * 1024;
const TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-chromium-leveldb-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create fixture root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn directory(&self, relative: impl AsRef<Path>) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(&path).expect("create fixture directory");
        path
    }

    fn write(&self, relative: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(&path, bytes).expect("write fixture");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn chromium_profile(fixture: &TestDirectory) -> BrowserProfile {
    let home = fixture.directory("home");
    let config = fixture.directory("home/config");
    fixture.directory("home/config/chromium/Default");
    let roots = BrowserProfileRoots::new(home, config, None::<&Path>).expect("fixture roots");
    BrowserProfileDiscovery::with_roots(roots)
        .discover()
        .profiles()
        .first()
        .expect("Chromium fixture profile")
        .clone()
}

fn profile_for(fixture: &TestDirectory, browser: BrowserKind) -> BrowserProfile {
    let home = fixture.directory("home");
    let config = fixture.directory("home/config");
    let relative = match browser {
        BrowserKind::Chromium => "chromium/Default",
        BrowserKind::GoogleChrome => "google-chrome/Default",
        BrowserKind::Brave => "BraveSoftware/Brave-Browser/Default",
        BrowserKind::BraveOrigin => "BraveSoftware/Brave-Origin/Default",
        BrowserKind::MicrosoftEdge => "microsoft-edge/Default",
        BrowserKind::Firefox | BrowserKind::Zen => {
            unreachable!("test helper supports Chromium layouts only")
        }
    };
    fixture.directory(Path::new("home/config").join(relative));
    let roots = BrowserProfileRoots::new(home, config, None::<&Path>).expect("fixture roots");
    BrowserProfileDiscovery::with_roots(roots)
        .discover()
        .profiles()
        .iter()
        .find(|profile| profile.browser() == browser)
        .expect("requested fixture profile")
        .clone()
}

fn firefox_profile(fixture: &TestDirectory) -> BrowserProfile {
    let home = fixture.directory("home");
    let config = fixture.directory("home/config");
    fixture.directory("home/.mozilla/firefox/Profiles/default");
    fixture.write(
        "home/.mozilla/firefox/profiles.ini",
        b"[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n",
    );
    let roots = BrowserProfileRoots::new(home, config, None::<&Path>).expect("fixture roots");
    BrowserProfileDiscovery::with_roots(roots)
        .discover()
        .profiles()
        .iter()
        .find(|profile| profile.browser() == BrowserKind::Firefox)
        .expect("Firefox fixture profile")
        .clone()
}

#[derive(Clone)]
enum BatchOperation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

fn write_batch(sequence: u64, operations: &[BatchOperation]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(operations.len())
            .expect("fixture operation count")
            .to_le_bytes(),
    );
    for operation in operations {
        match operation {
            BatchOperation::Put(key, value) => {
                output.push(1);
                put_slice(&mut output, key);
                put_slice(&mut output, value);
            }
            BatchOperation::Delete(key) => {
                output.push(0);
                put_slice(&mut output, key);
            }
        }
    }
    output
}

fn full_log(batch: &[u8]) -> Vec<u8> {
    physical_record(1, batch)
}

fn fragmented_log(batch: &[u8]) -> Vec<u8> {
    let first_end = batch.len() / 3;
    let middle_end = first_end * 2;
    [
        physical_record(2, &batch[..first_end]),
        physical_record(3, &batch[first_end..middle_end]),
        physical_record(4, &batch[middle_end..]),
    ]
    .concat()
}

fn block_fragmented_log(batch: &[u8]) -> Vec<u8> {
    assert!(batch.len() > LOG_BLOCK_BYTES);
    let first_length = LOG_BLOCK_BYTES - 7;
    let mut output = physical_record(2, &batch[..first_length]);
    assert_eq!(output.len(), LOG_BLOCK_BYTES);
    output.extend_from_slice(&physical_record(4, &batch[first_length..]));
    output
}

fn physical_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 7);
    output.extend_from_slice(&masked_crc32c_parts(record_type, payload).to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("fixture physical record length")
            .to_le_bytes(),
    );
    output.push(record_type);
    output.extend_from_slice(payload);
    output
}

fn local_key(origin: &str, key: &str) -> Vec<u8> {
    let mut bytes = vec![b'_'];
    bytes.extend_from_slice(origin.as_bytes());
    bytes.push(0);
    bytes.push(1);
    bytes.extend_from_slice(key.as_bytes());
    bytes
}

fn legacy_local_key(origin: &str, key: &str) -> Vec<u8> {
    let mut bytes = origin.as_bytes().to_vec();
    bytes.push(0);
    bytes.push(1);
    bytes.extend_from_slice(key.as_bytes());
    bytes
}

fn local_value(value: &str) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn local_utf16_value(value: &str) -> Vec<u8> {
    let mut bytes = vec![0];
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

#[derive(Clone)]
struct TableRecord {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    sequence: u64,
}

#[derive(Clone, Copy)]
enum TableCompression {
    Raw,
    Snappy,
}

fn table(records: &[TableRecord], compression: TableCompression) -> Vec<u8> {
    let data_entries = records
        .iter()
        .map(|record| {
            let mut internal = record.key.clone();
            let value_type = u64::from(record.value.is_some());
            internal.extend_from_slice(&((record.sequence << 8) | value_type).to_le_bytes());
            (internal, record.value.clone().unwrap_or_default())
        })
        .collect::<Vec<_>>();
    let data_block = prefix_block(&data_entries);
    let mut output = Vec::new();
    let data_handle = append_table_block(&mut output, &data_block, compression);

    let meta_block = prefix_block(&[]);
    let meta_handle = append_table_block(&mut output, &meta_block, TableCompression::Raw);
    let index_key = data_entries
        .last()
        .map_or_else(|| b"index".to_vec(), |entry| entry.0.clone());
    let index_block = prefix_block(&[(index_key, encode_handle(data_handle))]);
    let index_handle = append_table_block(&mut output, &index_block, TableCompression::Raw);

    let mut footer = Vec::new();
    footer.extend_from_slice(&encode_handle(meta_handle));
    footer.extend_from_slice(&encode_handle(index_handle));
    footer.resize(40, 0);
    footer.extend_from_slice(&TABLE_MAGIC.to_le_bytes());
    output.extend_from_slice(&footer);
    output
}

fn prefix_amplification_table(key_bytes: usize, entry_count: usize) -> Vec<u8> {
    let mut internal_key = vec![b'k'; key_bytes];
    internal_key.extend_from_slice(&(1_u64 << 8).to_le_bytes());
    let mut data_block = Vec::new();
    put_varint(&mut data_block, 0);
    put_varint(
        &mut data_block,
        u64::try_from(internal_key.len()).expect("amplification key length"),
    );
    put_varint(&mut data_block, 0);
    data_block.extend_from_slice(&internal_key);
    for _ in 1..entry_count {
        put_varint(
            &mut data_block,
            u64::try_from(internal_key.len()).expect("shared key length"),
        );
        put_varint(&mut data_block, 0);
        put_varint(&mut data_block, 0);
    }
    data_block.extend_from_slice(&0_u32.to_le_bytes());
    data_block.extend_from_slice(&1_u32.to_le_bytes());

    let mut output = Vec::new();
    let data_handle = append_table_block(&mut output, &data_block, TableCompression::Raw);
    let meta_block = prefix_block(&[]);
    let meta_handle = append_table_block(&mut output, &meta_block, TableCompression::Raw);
    let index_block = prefix_block(&[(b"index".to_vec(), encode_handle(data_handle))]);
    let index_handle = append_table_block(&mut output, &index_block, TableCompression::Raw);
    let mut footer = Vec::new();
    footer.extend_from_slice(&encode_handle(meta_handle));
    footer.extend_from_slice(&encode_handle(index_handle));
    footer.resize(40, 0);
    footer.extend_from_slice(&TABLE_MAGIC.to_le_bytes());
    output.extend_from_slice(&footer);
    output
}

fn prefix_block(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut restarts = Vec::new();
    for (key, value) in entries {
        restarts.push(u32::try_from(output.len()).expect("fixture restart offset"));
        put_varint(&mut output, 0);
        put_varint(
            &mut output,
            u64::try_from(key.len()).expect("fixture key length"),
        );
        put_varint(
            &mut output,
            u64::try_from(value.len()).expect("fixture value length"),
        );
        output.extend_from_slice(key);
        output.extend_from_slice(value);
    }
    if restarts.is_empty() {
        restarts.push(0);
    }
    for restart in &restarts {
        output.extend_from_slice(&restart.to_le_bytes());
    }
    output.extend_from_slice(
        &u32::try_from(restarts.len())
            .expect("fixture restart count")
            .to_le_bytes(),
    );
    output
}

fn append_table_block(
    output: &mut Vec<u8>,
    block: &[u8],
    compression: TableCompression,
) -> (usize, usize) {
    let offset = output.len();
    let (stored, compression_type) = match compression {
        TableCompression::Raw => (block.to_vec(), 0),
        TableCompression::Snappy => (snappy_literal(block), 1),
    };
    output.extend_from_slice(&stored);
    output.push(compression_type);
    output.extend_from_slice(&masked_crc32c_block(&stored, compression_type).to_le_bytes());
    (offset, stored.len())
}

fn encode_handle((offset, size): (usize, usize)) -> Vec<u8> {
    let mut output = Vec::new();
    put_varint(&mut output, u64::try_from(offset).expect("fixture offset"));
    put_varint(&mut output, u64::try_from(size).expect("fixture size"));
    output
}

fn snappy_literal(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    put_varint(
        &mut output,
        u64::try_from(bytes.len()).expect("fixture Snappy length"),
    );
    let minus_one = bytes.len().checked_sub(1).expect("nonempty fixture block");
    if minus_one < 60 {
        output.push(u8::try_from(minus_one << 2).expect("short Snappy tag"));
    } else if u8::try_from(minus_one).is_ok() {
        output.push(60 << 2);
        output.push(u8::try_from(minus_one).expect("one-byte literal length"));
    } else if u16::try_from(minus_one).is_ok() {
        output.push(61 << 2);
        output.extend_from_slice(
            &u16::try_from(minus_one)
                .expect("two-byte literal length")
                .to_le_bytes(),
        );
    } else {
        panic!("fixture block exceeds literal-only helper")
    }
    output.extend_from_slice(bytes);
    output
}

fn put_slice(output: &mut Vec<u8>, value: &[u8]) {
    put_varint(
        output,
        u64::try_from(value.len()).expect("fixture slice length"),
    );
    output.extend_from_slice(value);
}

fn put_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).expect("varint payload") | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).expect("varint terminal"));
}

fn masked_crc32c_parts(record_type: u8, payload: &[u8]) -> u32 {
    let crc = crc32c_extend(crc32c_extend(!0_u32, &[record_type]), payload);
    (!crc).rotate_right(15).wrapping_add(0xa282_ead8)
}

fn masked_crc32c_block(block: &[u8], compression: u8) -> u32 {
    let crc = crc32c_extend(crc32c_extend(!0_u32, block), &[compression]);
    (!crc).rotate_right(15).wrapping_add(0xa282_ead8)
}

fn crc32c_extend(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0x82f6_3b78
            };
        }
    }
    crc
}

fn values(reader: &ChromiumLevelDbReader, origin: &str) -> BTreeMap<String, (String, u64)> {
    reader
        .local_storage_entries(&ChromiumHttpsOrigin::parse(origin).expect("fixture origin"))
        .expect("local-storage projection")
        .into_iter()
        .map(|entry| {
            (
                entry.expose_key().to_owned(),
                (entry.expose_value().to_owned(), entry.sequence()),
            )
        })
        .collect()
}

#[test]
fn reads_full_and_fragmented_logs_with_sequence_ordering_and_tombstones() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    let relative = "Local Storage/leveldb";
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let origin = "https://example.test";

    let old = write_batch(
        10,
        &[
            BatchOperation::Put(local_key(origin, "kept"), local_value("old")),
            BatchOperation::Put(local_key(origin, "deleted"), local_value("present")),
        ],
    );
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000009.log",
        full_log(&old),
    );
    let newest = write_batch(
        30,
        &[
            BatchOperation::Put(local_key(origin, "kept"), local_value("new")),
            BatchOperation::Delete(local_key(origin, "deleted")),
        ],
    );
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.log",
        fragmented_log(&newest),
    );

    let reader = ChromiumLevelDbReader::open(&profile, relative).expect("read logs");
    assert_eq!(
        values(&reader, origin),
        BTreeMap::from([("kept".to_owned(), ("new".to_owned(), 30))])
    );
}

#[test]
fn reassembles_a_write_batch_across_physical_log_blocks() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let large = "x".repeat(LOG_BLOCK_BYTES + 512);
    let batch = write_batch(
        44,
        &[BatchOperation::Put(
            b"plain-key".to_vec(),
            large.into_bytes(),
        )],
    );
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.log",
        block_fragmented_log(&batch),
    );
    let reader = ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
        .expect("read block-fragmented log");
    assert_eq!(reader.source_file_count(), 1);
    assert_eq!(reader.text_entries().expect("text entries").len(), 1);
}

#[test]
fn reads_raw_and_snappy_tables_and_resolves_versions_by_sequence_not_filename() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let origin = "https://tables.test";
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/999999.ldb",
        table(
            &[TableRecord {
                key: local_key(origin, "theme"),
                value: Some(local_value("older")),
                sequence: 20,
            }],
            TableCompression::Raw,
        ),
    );
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.ldb",
        table(
            &[
                TableRecord {
                    key: local_key(origin, "theme"),
                    value: Some(local_value("newest")),
                    sequence: 70,
                },
                TableRecord {
                    key: local_key(origin, "removed"),
                    value: None,
                    sequence: 71,
                },
            ],
            TableCompression::Snappy,
        ),
    );
    let old_removed = write_batch(
        40,
        &[BatchOperation::Put(
            local_key(origin, "removed"),
            local_value("must-not-resurrect"),
        )],
    );
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/555555.log",
        full_log(&old_removed),
    );

    let reader = ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
        .expect("read table fixtures");
    assert_eq!(
        values(&reader, origin),
        BTreeMap::from([("theme".to_owned(), ("newest".to_owned(), 70))])
    );
}

#[test]
fn exact_https_origin_matching_handles_partitions_and_legacy_host_only_keys() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let operations = [
        BatchOperation::Put(
            local_key("https://exact.test/^0https://partition.test", "partitioned"),
            local_value("yes"),
        ),
        BatchOperation::Put(legacy_local_key("exact.test", "legacy"), local_value("yes")),
        BatchOperation::Put(
            local_key("http://exact.test", "wrong-scheme"),
            local_value("no"),
        ),
        BatchOperation::Put(
            local_key("https://exact.test:8443", "wrong-port"),
            local_value("no"),
        ),
        BatchOperation::Put(
            local_key("https://sub.exact.test", "subdomain"),
            local_value("no"),
        ),
        BatchOperation::Put(
            local_key("https://exact.test.evil", "suffix"),
            local_value("no"),
        ),
        BatchOperation::Put(
            local_key(" https://exact.test ", "whitespace"),
            local_value("no"),
        ),
        BatchOperation::Put(local_key("https://exact.test", ""), local_value("")),
        BatchOperation::Put(
            local_key("https://exact.test", "utf16"),
            local_utf16_value("snowman ☃"),
        ),
        BatchOperation::Put(
            local_key("https://exact.test", "controls"),
            local_value("\nkept\n"),
        ),
    ];
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.log",
        full_log(&write_batch(100, &operations)),
    );
    let reader = ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
        .expect("read origin fixture");
    assert_eq!(
        values(&reader, "https://exact.test"),
        BTreeMap::from([
            (String::new(), (String::new(), 107)),
            ("controls".to_owned(), ("\nkept\n".to_owned(), 109)),
            ("legacy".to_owned(), ("yes".to_owned(), 101)),
            ("partitioned".to_owned(), ("yes".to_owned(), 100)),
            ("utf16".to_owned(), ("snowman ☃".to_owned(), 108)),
        ])
    );
    assert!(values(&reader, "https://exact.test:444").is_empty());

    for invalid in [
        "http://exact.test",
        "https://exact.test/path",
        "https://user@exact.test",
        "https://exact.test?query",
        "https://exact.test#fragment",
    ] {
        assert_eq!(
            ChromiumHttpsOrigin::parse(invalid),
            Err(ChromiumLevelDbError::InvalidOrigin)
        );
    }
}

#[test]
fn text_and_token_scans_return_only_newest_live_bounded_values() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let token = "header.payload.signature-with-a-long-token-candidate-1234567890";
    let deleted_token = "deleted.payload.signature-that-must-never-be-returned-1234567890";
    let operations = [
        BatchOperation::Put(
            b"session".to_vec(),
            format!("prefix {token} suffix").into_bytes(),
        ),
        BatchOperation::Put(b"removed".to_vec(), deleted_token.as_bytes().to_vec()),
        BatchOperation::Delete(b"removed".to_vec()),
    ];
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.log",
        full_log(&write_batch(8, &operations)),
    );
    let reader =
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb").expect("read token fixture");
    let text = reader.text_entries().expect("text entries");
    assert_eq!(text.len(), 1);
    assert_eq!(text[0].expose_key(), "session");
    assert!(text[0].expose_value().contains(token));
    let tokens = reader
        .token_candidates(32)
        .expect("bounded token candidates")
        .into_iter()
        .map(|candidate| candidate.expose_secret().to_owned())
        .collect::<Vec<_>>();
    assert!(tokens.contains(&token.to_owned()));
    assert!(!tokens.contains(&deleted_token.to_owned()));
    assert_eq!(
        reader.token_candidates(0).expect_err("zero minimum"),
        ChromiumLevelDbError::InvalidTokenPolicy
    );
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn observe(path: &Path) -> Observation {
    let metadata = fs::symlink_metadata(path).expect("fixture metadata");
    Observation {
        bytes: fs::read(path).expect("fixture bytes"),
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[test]
fn source_bytes_and_identity_are_unchanged_and_reads_are_deterministic() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let source = fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.log",
        full_log(&write_batch(
            5,
            &[BatchOperation::Put(
                local_key("https://stable.test", "key"),
                local_value("value"),
            )],
        )),
    );
    let before = observe(&source);
    let first =
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb").expect("first stable read");
    let first_values = values(&first, "https://stable.test");
    let second =
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb").expect("second stable read");
    assert_eq!(values(&second, "https://stable.test"), first_values);
    assert_eq!(observe(&source), before);
    assert!(
        !source
            .parent()
            .expect("source parent")
            .join("LOCK")
            .exists()
    );
}

#[test]
fn traversal_symlinks_fifos_and_non_utf8_names_are_rejected() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "../leveldb").expect_err("traversal"),
        ChromiumLevelDbError::InvalidRelativePath
    );
    for invalid in [
        PathBuf::new(),
        PathBuf::from("."),
        fixture.path().to_path_buf(),
    ] {
        assert_eq!(
            ChromiumLevelDbReader::open(&profile, invalid).expect_err("invalid relative path"),
            ChromiumLevelDbError::InvalidRelativePath
        );
    }
    let non_utf8_relative = PathBuf::from(OsString::from_vec(vec![b'x', 0xff]));
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, non_utf8_relative)
            .expect_err("non-UTF-8 relative path"),
        ChromiumLevelDbError::InvalidRelativePath
    );

    let outside_directory = fixture.directory("outside-leveldb");
    let linked_directory = fixture
        .path()
        .join("home/config/chromium/Default/linked-leveldb");
    symlink(&outside_directory, &linked_directory).expect("fixture directory symlink");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "linked-leveldb").expect_err("symlink directory"),
        ChromiumLevelDbError::UnsafeLayout
    );

    let outside = fixture.write("outside.log", full_log(&write_batch(1, &[])));
    symlink(
        &outside,
        fixture
            .path()
            .join("home/config/chromium/Default/Local Storage/leveldb/000001.log"),
    )
    .expect("fixture symlink");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb").expect_err("symlink file"),
        ChromiumLevelDbError::UnsafeLayout
    );
    fs::remove_file(
        fixture
            .path()
            .join("home/config/chromium/Default/Local Storage/leveldb/000001.log"),
    )
    .expect("remove fixture symlink");

    let fifo = fixture
        .path()
        .join("home/config/chromium/Default/Local Storage/leveldb/fifo");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("fixture FIFO");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb").expect_err("FIFO entry"),
        ChromiumLevelDbError::UnsafeLayout
    );
    fs::remove_file(&fifo).expect("remove fixture FIFO");

    let non_utf8_name = OsString::from_vec(vec![b'n', b'a', b'm', b'e', 0xff]);
    let non_utf8_path = fixture
        .path()
        .join("home/config/chromium/Default/Local Storage/leveldb")
        .join(&non_utf8_name);
    fs::write(&non_utf8_path, []).expect("non-UTF-8 fixture entry");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("non-UTF-8 entry"),
        ChromiumLevelDbError::UnsafeLayout
    );
    fs::remove_file(&non_utf8_path).expect("remove non-UTF-8 entry");
}

#[test]
fn post_discovery_ancestor_symlink_swap_cannot_redirect_profile_reads() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    let original_browser_root = fixture.path().join("home/config/chromium");
    fs::rename(
        &original_browser_root,
        fixture.path().join("original-chromium"),
    )
    .expect("move discovered browser root");

    fixture.directory("outside/chromium/Default/Local Storage/leveldb");
    fixture.write(
        "outside/chromium/Default/Local Storage/leveldb/000001.log",
        full_log(&write_batch(
            1,
            &[BatchOperation::Put(
                local_key("https://redirect.test", "secret"),
                local_value("must-not-be-read"),
            )],
        )),
    );
    symlink(
        fixture.path().join("outside/chromium"),
        &original_browser_root,
    )
    .expect("replace profile ancestor with symlink");

    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("ancestor symlink replacement"),
        ChromiumLevelDbError::InvalidProfile
    );
}

#[test]
fn file_and_aggregate_size_and_count_bounds_are_rejected() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let oversized = fixture
        .path()
        .join("home/config/chromium/Default/Local Storage/leveldb/000002.ldb");
    fs::File::create(&oversized)
        .expect("oversized fixture")
        .set_len(32 * 1024 * 1024 + 1)
        .expect("sparse oversized fixture");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("oversized table"),
        ChromiumLevelDbError::TooLarge
    );
    fs::remove_file(&oversized).expect("remove oversized fixture");

    let mut aggregate_files = Vec::new();
    for index in 10..13 {
        let path = fixture.path().join(format!(
            "home/config/chromium/Default/Local Storage/leveldb/{index:06}.ldb"
        ));
        fs::File::create(&path)
            .expect("aggregate fixture")
            .set_len(22 * 1024 * 1024)
            .expect("sparse aggregate fixture");
        aggregate_files.push(path);
    }
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("aggregate bound"),
        ChromiumLevelDbError::TooLarge
    );
    for path in aggregate_files {
        fs::remove_file(path).expect("remove aggregate fixture");
    }

    for index in 0..257 {
        fs::write(
            fixture.path().join(format!(
                "home/config/chromium/Default/Local Storage/leveldb/{index:06}.log"
            )),
            [],
        )
        .expect("file-count fixture");
    }
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("file-count bound"),
        ChromiumLevelDbError::TooManyEntries
    );
}

#[test]
fn malformed_checksums_sequences_snappy_and_conflicting_versions_fail_closed() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    let directory = fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let path = directory.join("000001.log");

    let mut bad_checksum = full_log(&write_batch(1, &[BatchOperation::Delete(b"x".to_vec())]));
    bad_checksum[0] ^= 0xff;
    fs::write(&path, bad_checksum).expect("bad checksum fixture");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb").expect_err("bad checksum"),
        ChromiumLevelDbError::Malformed
    );

    fs::write(
        &path,
        full_log(&write_batch(
            (1_u64 << 56) - 1,
            &[
                BatchOperation::Delete(b"x".to_vec()),
                BatchOperation::Delete(b"y".to_vec()),
            ],
        )),
    )
    .expect("sequence overflow fixture");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("sequence overflow"),
        ChromiumLevelDbError::Malformed
    );

    fs::remove_file(&path).expect("remove log fixture");
    let mut bad_snappy = table(
        &[TableRecord {
            key: b"key".to_vec(),
            value: Some(b"value".to_vec()),
            sequence: 1,
        }],
        TableCompression::Snappy,
    );
    bad_snappy[0] ^= 0x7f;
    fs::write(directory.join("000002.ldb"), bad_snappy).expect("bad Snappy fixture");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("bad Snappy/checksum"),
        ChromiumLevelDbError::Malformed
    );

    fs::remove_file(directory.join("000002.ldb")).expect("remove table fixture");
    fs::write(
        directory.join("000003.log"),
        full_log(&write_batch(
            9,
            &[BatchOperation::Put(b"same".to_vec(), b"one".to_vec())],
        )),
    )
    .expect("first conflicting version");
    fs::write(
        directory.join("000004.log"),
        full_log(&write_batch(
            9,
            &[BatchOperation::Put(b"same".to_vec(), b"two".to_vec())],
        )),
    )
    .expect("second conflicting version");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("conflicting version"),
        ChromiumLevelDbError::Malformed
    );
}

#[test]
fn entry_field_text_and_token_result_bounds_fail_closed() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    let directory = fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let log = directory.join("000001.log");

    let mut excessive_entries = Vec::new();
    excessive_entries.extend_from_slice(&1_u64.to_le_bytes());
    excessive_entries.extend_from_slice(&65_537_u32.to_le_bytes());
    fs::write(&log, full_log(&excessive_entries)).expect("entry-count fixture");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("entry-count bound"),
        ChromiumLevelDbError::TooManyEntries
    );

    let mut excessive_field = Vec::new();
    excessive_field.extend_from_slice(&1_u64.to_le_bytes());
    excessive_field.extend_from_slice(&1_u32.to_le_bytes());
    excessive_field.push(1);
    put_varint(&mut excessive_field, 4 * 1024 * 1024 + 1);
    fs::write(&log, full_log(&excessive_field)).expect("field-size fixture");
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("field-size bound"),
        ChromiumLevelDbError::TooLarge
    );

    fs::remove_file(&log).expect("remove bounds log");
    let origin = "https://bounded.test";
    let mut excessive_text = vec![1];
    excessive_text.resize(256 * 1024 + 2, b'x');
    fs::write(
        directory.join("000002.ldb"),
        table(
            &[TableRecord {
                key: local_key(origin, "large"),
                value: Some(excessive_text),
                sequence: 1,
            }],
            TableCompression::Raw,
        ),
    )
    .expect("text-size fixture");
    let reader = ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
        .expect("parse bounded text fixture");
    assert_eq!(
        reader
            .local_storage_entries(&ChromiumHttpsOrigin::parse(origin).expect("origin"))
            .expect_err("text-size bound"),
        ChromiumLevelDbError::TooLarge
    );

    fs::remove_file(directory.join("000002.ldb")).expect("remove text table");
    let operations = (0..257)
        .map(|index| {
            BatchOperation::Put(
                format!("key {index}").into_bytes(),
                format!("candidate-{index:03}-abcdefgh").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    fs::write(&log, full_log(&write_batch(1, &operations))).expect("token-count fixture");
    let reader = ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
        .expect("parse token-count fixture");
    assert_eq!(
        reader.token_candidates(8).expect_err("token-result cap"),
        ChromiumLevelDbError::TooManyEntries
    );
    assert_eq!(
        reader
            .token_candidates(16 * 1024 + 1)
            .expect_err("token policy cap"),
        ChromiumLevelDbError::InvalidTokenPolicy
    );
}

#[test]
fn prefix_compression_cannot_amplify_reconstructed_entries_past_budget() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    fixture.directory("home/config/chromium/Default/Local Storage/leveldb");
    let compact_amplification = prefix_amplification_table(1024 * 1024, 65);
    assert!(compact_amplification.len() < 2 * 1024 * 1024);
    fixture.write(
        "home/config/chromium/Default/Local Storage/leveldb/000001.ldb",
        compact_amplification,
    );

    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "Local Storage/leveldb")
            .expect_err("reconstructed-entry byte budget"),
        ChromiumLevelDbError::TooLarge
    );
}

#[test]
fn browser_gate_missing_paths_and_diagnostics_are_stable_and_redacted() {
    let fixture = TestDirectory::new();
    let profile = chromium_profile(&fixture);
    let gecko = firefox_profile(&fixture);
    assert_eq!(
        ChromiumLevelDbReader::open(&gecko, "storage").expect_err("unsupported Gecko browser"),
        ChromiumLevelDbError::UnsupportedBrowser
    );
    assert_eq!(
        ChromiumLevelDbReader::open(&profile, "missing").expect_err("missing directory"),
        ChromiumLevelDbError::Missing
    );
    for browser in [
        BrowserKind::GoogleChrome,
        BrowserKind::Brave,
        BrowserKind::BraveOrigin,
        BrowserKind::MicrosoftEdge,
    ] {
        let supported = profile_for(&fixture, browser);
        fixture.directory(supported.path().join("Store"));
        let reader = ChromiumLevelDbReader::open(&supported, "Store").expect("supported browser");
        assert_eq!(reader.source_file_count(), 0);
    }

    fixture.directory("home/config/chromium/Default/Store");
    let reader = ChromiumLevelDbReader::open(&profile, "Store").expect("empty reader");
    let diagnostic = format!(
        "{reader:?} {:?} {:?}",
        ChromiumLevelDbError::Malformed,
        ChromiumHttpsOrigin::parse("https://diagnostic-canary.test").expect("origin")
    );
    assert!(!diagnostic.contains("diagnostic-canary"));
    assert!(!diagnostic.contains(fixture.path().to_string_lossy().as_ref()));
    assert!(diagnostic.len() < 256);
}
