use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use oab_providers::browser_profile::{
    BrowserKind, BrowserProfile, BrowserProfileConfigError, BrowserProfileDiscovery,
    BrowserProfileIssueKind, BrowserProfileOrigin, BrowserProfileReport, BrowserProfileRoots,
    FlatpakProfileDiscovery,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-browser-profile-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create browser-profile fixture root");
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

    fn write(&self, relative: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().expect("fixture file parent"))
            .expect("create fixture file parent");
        fs::write(&path, contents).expect("write fixture file");
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn explicit_discovery(
    fixture: &TestDirectory,
    flatpak_root: Option<&Path>,
) -> BrowserProfileDiscovery {
    let home = fixture.directory("home");
    let config = fixture.directory("home/config");
    let roots = BrowserProfileRoots::new(&home, &config, flatpak_root)
        .expect("valid injected fixture roots");
    BrowserProfileDiscovery::with_roots(roots)
}

fn kinds(report: &BrowserProfileReport) -> Vec<BrowserKind> {
    report
        .profiles()
        .iter()
        .map(BrowserProfile::browser)
        .collect()
}

fn issue_kinds(report: &BrowserProfileReport) -> Vec<BrowserProfileIssueKind> {
    report.issues().iter().map(|issue| issue.kind()).collect()
}

fn write_firefox_ini(fixture: &TestDirectory, contents: impl AsRef<[u8]>) {
    fixture.write("home/.mozilla/firefox/profiles.ini", contents);
}

#[test]
fn disabled_discovery_does_not_require_paths_and_injected_roots_are_validated() {
    let disabled = BrowserProfileDiscovery::default();
    assert!(disabled.discover().is_empty());
    assert_eq!(
        format!("{disabled:?}"),
        "BrowserProfileDiscovery { enabled: false, flatpak_enabled: false }"
    );

    let empty = BTreeMap::new();
    assert_eq!(
        BrowserProfileRoots::from_environment(&empty, FlatpakProfileDiscovery::Disabled),
        Err(BrowserProfileConfigError::MissingHome)
    );

    let relative_home = BTreeMap::from([("HOME".to_owned(), "relative/home".to_owned())]);
    assert_eq!(
        BrowserProfileRoots::from_environment(&relative_home, FlatpakProfileDiscovery::Disabled),
        Err(BrowserProfileConfigError::InvalidRoot)
    );

    let relative_xdg = BTreeMap::from([
        ("HOME".to_owned(), "/safe/home".to_owned()),
        ("XDG_CONFIG_HOME".to_owned(), "relative/config".to_owned()),
    ]);
    assert_eq!(
        BrowserProfileRoots::from_environment(&relative_xdg, FlatpakProfileDiscovery::Disabled),
        Err(BrowserProfileConfigError::InvalidRoot)
    );

    let environment = BTreeMap::from([("HOME".to_owned(), "/safe/home".to_owned())]);
    let roots =
        BrowserProfileRoots::from_environment(&environment, FlatpakProfileDiscovery::Enabled)
            .expect("absolute injected HOME");
    assert_eq!(
        format!("{roots:?}"),
        "BrowserProfileRoots { home: \"<redacted>\", config_home: \"<redacted>\", flatpak_enabled: true }"
    );
}

#[test]
fn injected_environment_honors_xdg_fallback_and_flatpak_opt_in() {
    let fixture = TestDirectory::new();
    let home = fixture.directory("home");
    let xdg = fixture.directory("xdg");
    fixture.directory("xdg/chromium/Default");
    fixture.directory("home/.var/app/com.google.Chrome/config/google-chrome/Default");
    fixture.directory("home/.config/microsoft-edge/Default");

    let with_xdg = BTreeMap::from([
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
        (
            "XDG_CONFIG_HOME".to_owned(),
            xdg.to_string_lossy().into_owned(),
        ),
    ]);
    let native = BrowserProfileDiscovery::enabled_from_environment(
        &with_xdg,
        FlatpakProfileDiscovery::Disabled,
    )
    .expect("injected XDG roots")
    .discover();
    assert_eq!(kinds(&native), vec![BrowserKind::Chromium]);

    let with_flatpak = BrowserProfileDiscovery::enabled_from_environment(
        &with_xdg,
        FlatpakProfileDiscovery::Enabled,
    )
    .expect("injected Flatpak root")
    .discover();
    assert_eq!(
        kinds(&with_flatpak),
        vec![BrowserKind::Chromium, BrowserKind::GoogleChrome]
    );
    assert_eq!(
        with_flatpak.profiles()[1].origin(),
        BrowserProfileOrigin::Flatpak
    );

    let without_xdg = BTreeMap::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
    let fallback = BrowserProfileDiscovery::enabled_from_environment(
        &without_xdg,
        FlatpakProfileDiscovery::Disabled,
    )
    .expect("injected HOME fallback")
    .discover();
    assert_eq!(kinds(&fallback), vec![BrowserKind::MicrosoftEdge]);
}

#[test]
fn discovers_all_native_browser_layouts_in_deterministic_order() {
    let fixture = TestDirectory::new();
    let chromium = fixture.directory("home/config/chromium/Default");
    let chrome = fixture.directory("home/config/google-chrome/Profile 2");
    let brave = fixture.directory("home/config/BraveSoftware/Brave-Browser/Default");
    let origin = fixture.directory("home/config/BraveSoftware/Brave-Origin/Default");
    let edge = fixture.directory("home/config/microsoft-edge/Default");
    let firefox_primary = fixture.directory("home/.mozilla/firefox/Profiles/primary");
    let firefox_secondary = fixture.directory("home/.mozilla/firefox/Profiles/secondary");
    write_firefox_ini(
        &fixture,
        b"[Profile8]\nName=Secondary\nIsRelative=1\nPath=Profiles/secondary\n\
          [Profile3]\nName=Primary\nIsRelative=1\nPath=Profiles/primary\nDefault=1\n",
    );
    let zen = fixture.directory("home/.zen/Profiles/default");
    fixture.write(
        "home/.zen/profiles.ini",
        b"[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/default\nDefault=1\n",
    );

    let report = explicit_discovery(&fixture, None).discover();

    assert!(report.issues().is_empty(), "issues: {:?}", report.issues());
    assert_eq!(
        kinds(&report),
        vec![
            BrowserKind::Chromium,
            BrowserKind::GoogleChrome,
            BrowserKind::Brave,
            BrowserKind::BraveOrigin,
            BrowserKind::MicrosoftEdge,
            BrowserKind::Firefox,
            BrowserKind::Firefox,
            BrowserKind::Zen,
        ]
    );
    let expected = [
        chromium,
        chrome,
        brave,
        origin,
        edge,
        firefox_primary,
        firefox_secondary,
        zen,
    ];
    for (profile, expected_path) in report.profiles().iter().zip(expected) {
        assert_eq!(profile.origin(), BrowserProfileOrigin::Native);
        assert_eq!(
            profile.path(),
            expected_path.canonicalize().expect("canonical fixture")
        );
    }
}

#[test]
fn flatpak_discovery_is_opt_in_and_native_profiles_have_global_precedence() {
    let fixture = TestDirectory::new();
    fixture.directory("home/config/chromium/Default");
    let flatpak = fixture.directory("flatpak");
    fixture.directory("flatpak/com.google.Chrome/config/google-chrome/Default");
    fixture.directory("flatpak/org.mozilla.firefox/.mozilla/firefox/Profiles/shared");
    fixture.write(
        "flatpak/org.mozilla.firefox/.mozilla/firefox/profiles.ini",
        b"[Profile0]\nPath=Profiles/shared\nIsRelative=1\nDefault=1\n\
          [Profile1]\nPath=Profiles/shared\nIsRelative=1\n",
    );
    fixture.directory("flatpak/app.zen_browser.zen/.zen/Profiles/current");
    fixture.write(
        "flatpak/app.zen_browser.zen/.zen/profiles.ini",
        b"[Profile0]\nPath=Profiles/current\nIsRelative=1\n",
    );
    fixture.directory("flatpak/io.github.zen_browser.zen/.zen/Profiles/legacy");
    fixture.write(
        "flatpak/io.github.zen_browser.zen/.zen/profiles.ini",
        b"[Profile0]\nPath=Profiles/legacy\nIsRelative=1\n",
    );

    let native_only = explicit_discovery(&fixture, None).discover();
    assert_eq!(kinds(&native_only), vec![BrowserKind::Chromium]);

    let report = explicit_discovery(&fixture, Some(&flatpak)).discover();
    assert!(report.issues().is_empty(), "issues: {:?}", report.issues());
    assert_eq!(
        kinds(&report),
        vec![
            BrowserKind::Chromium,
            BrowserKind::GoogleChrome,
            BrowserKind::Firefox,
            BrowserKind::Zen,
            BrowserKind::Zen,
        ]
    );
    assert_eq!(report.profiles()[0].origin(), BrowserProfileOrigin::Native);
    assert!(
        report.profiles()[1..]
            .iter()
            .all(|profile| profile.origin() == BrowserProfileOrigin::Flatpak)
    );
}

#[test]
fn chromium_symlink_escapes_and_non_directories_are_rejected() {
    let fixture = TestDirectory::new();
    fixture.directory("home/config/chromium/Default");
    let outside = fixture.directory("outside");
    symlink(
        &outside,
        fixture.path().join("home/config/chromium/Profile 1"),
    )
    .expect("create escaping profile symlink");
    fixture.write("home/config/chromium/Profile 2", b"not a directory");
    symlink(&outside, fixture.path().join("home/config/google-chrome"))
        .expect("create escaping browser-root symlink");

    let report = explicit_discovery(&fixture, None).discover();

    assert_eq!(kinds(&report), vec![BrowserKind::Chromium]);
    assert_eq!(
        issue_kinds(&report),
        vec![
            BrowserProfileIssueKind::UnsafePath,
            BrowserProfileIssueKind::UnsupportedFileType,
            BrowserProfileIssueKind::UnsafePath,
        ]
    );
}

#[test]
fn gecko_parser_accepts_comments_crlf_defaults_and_safe_absolute_paths() {
    let fixture = TestDirectory::new();
    let default = fixture.directory("home/.mozilla/firefox/Profiles/default");
    let absolute = fixture.directory("home/.mozilla/firefox/Profiles/absolute");
    let ini = format!(
        "; generated fixture\r\n[General]\r\nStartWithLastProfile=1\r\n\
         [Profile7]\r\nName=Absolute\r\nIsRelative=0\r\nPath={}\r\n\
         [InstallABC]\r\nDefault=Profiles/default\r\n\
         [Profile2]\r\nName=Default\r\nIsRelative=1\r\nPath=Profiles/default\r\nDefault=1\r\n",
        absolute.display()
    );
    write_firefox_ini(&fixture, ini);

    let report = explicit_discovery(&fixture, None).discover();

    assert!(report.issues().is_empty(), "issues: {:?}", report.issues());
    let paths = report
        .profiles()
        .iter()
        .map(|profile| profile.path().to_path_buf())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            default.canonicalize().expect("default profile"),
            absolute.canonicalize().expect("absolute profile"),
        ]
    );
}

#[test]
fn gecko_parent_absolute_and_symlink_escapes_do_not_hide_a_safe_profile() {
    let fixture = TestDirectory::new();
    let safe = fixture.directory("home/.mozilla/firefox/Profiles/safe");
    let outside = fixture.directory("outside");
    symlink(
        &outside,
        fixture
            .path()
            .join("home/.mozilla/firefox/Profiles/escaping-link"),
    )
    .expect("create Gecko escape symlink");
    let ini = format!(
        "[Profile0]\nPath=Profiles/safe\nIsRelative=1\n\
         [Profile1]\nPath=../outside\nIsRelative=1\n\
         [Profile2]\nPath=Profiles/escaping-link\nIsRelative=1\n\
         [Profile3]\nPath={}\nIsRelative=0\n",
        outside.display()
    );
    write_firefox_ini(&fixture, ini);

    let report = explicit_discovery(&fixture, None).discover();

    assert_eq!(report.profiles().len(), 1);
    assert_eq!(
        report.profiles()[0].path(),
        safe.canonicalize().expect("safe profile")
    );
    assert_eq!(
        issue_kinds(&report),
        vec![
            BrowserProfileIssueKind::UnsafePath,
            BrowserProfileIssueKind::UnsafePath,
            BrowserProfileIssueKind::UnsafePath,
        ]
    );
}

fn assert_firefox_ini_issue(contents: impl AsRef<[u8]>, expected: BrowserProfileIssueKind) {
    let fixture = TestDirectory::new();
    write_firefox_ini(&fixture, contents);
    let report = explicit_discovery(&fixture, None).discover();
    assert!(report.profiles().is_empty());
    assert_eq!(issue_kinds(&report), vec![expected]);
}

#[test]
fn profiles_ini_rejects_fifo_oversize_non_utf8_and_malformed_input() {
    {
        let fixture = TestDirectory::new();
        let root = fixture.directory("home/.mozilla/firefox");
        mkfifo(&root.join("profiles.ini"), Mode::S_IRUSR | Mode::S_IWUSR)
            .expect("create FIFO fixture");
        let report = explicit_discovery(&fixture, None).discover();
        assert_eq!(
            issue_kinds(&report),
            vec![BrowserProfileIssueKind::UnsupportedFileType]
        );
    }

    {
        let fixture = TestDirectory::new();
        let root = fixture.directory("home/.mozilla/firefox");
        let outside = fixture.write(
            "outside.ini",
            b"[Profile0]\nPath=Profiles/default\nIsRelative=1\n",
        );
        symlink(outside, root.join("profiles.ini")).expect("create escaping INI symlink");
        let report = explicit_discovery(&fixture, None).discover();
        assert_eq!(
            issue_kinds(&report),
            vec![BrowserProfileIssueKind::UnsupportedFileType]
        );
    }

    assert_firefox_ini_issue(
        vec![b'x'; 64 * 1024 + 1],
        BrowserProfileIssueKind::OversizedProfilesIni,
    );
    assert_firefox_ini_issue(
        b"[Profile0]\nPath=Profiles/\xff\n",
        BrowserProfileIssueKind::NonUtf8ProfilesIni,
    );
    assert_firefox_ini_issue(
        b"[Profile0]\nPath=Profiles/one\nPath=Profiles/two\n",
        BrowserProfileIssueKind::MalformedProfilesIni,
    );
    assert_firefox_ini_issue(
        b"[Profile0]\nPath=Profiles/one\nDefault=0\nDefault=0\n",
        BrowserProfileIssueKind::MalformedProfilesIni,
    );
}

#[test]
fn directory_and_ini_entry_limits_fail_closed() {
    {
        let fixture = TestDirectory::new();
        for index in 0..513 {
            fixture.directory(format!("home/config/chromium/irrelevant-{index}"));
        }
        let report = explicit_discovery(&fixture, None).discover();
        assert!(report.profiles().is_empty());
        assert_eq!(
            issue_kinds(&report),
            vec![BrowserProfileIssueKind::TooManyEntries]
        );
    }

    {
        let fixture = TestDirectory::new();
        for index in 0..129 {
            fixture.directory(format!("home/config/chromium/Profile {index}"));
        }
        let report = explicit_discovery(&fixture, None).discover();
        assert!(report.profiles().is_empty());
        assert_eq!(
            issue_kinds(&report),
            vec![BrowserProfileIssueKind::TooManyEntries]
        );
    }

    let mut ini = String::from("[General]\n");
    for index in 0..513 {
        writeln!(&mut ini, "Key{index}=value").expect("writing to a String cannot fail");
    }
    assert_firefox_ini_issue(ini, BrowserProfileIssueKind::TooManyEntries);
}

#[test]
fn non_utf8_directory_entries_fail_closed() {
    let fixture = TestDirectory::new();
    fixture.directory("home/config/chromium/Default");
    let invalid_name = OsString::from_vec(vec![b'P', b'r', b'o', 0xff]);
    fixture.directory(Path::new("home/config/chromium").join(invalid_name));

    let report = explicit_discovery(&fixture, None).discover();

    assert!(report.profiles().is_empty());
    assert_eq!(
        issue_kinds(&report),
        vec![BrowserProfileIssueKind::Unreadable]
    );
}

#[test]
fn public_diagnostics_redact_sensitive_paths() {
    let fixture = TestDirectory::new();
    fixture.directory("home/config/chromium/Default");
    fixture.write(
        "home/config/google-chrome/Default",
        b"not a profile directory",
    );
    let roots = BrowserProfileRoots::new(
        fixture.path().join("home"),
        fixture.path().join("home/config"),
        None::<&Path>,
    )
    .expect("fixture roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots.clone());
    let report = discovery.discover();
    let canary = fixture.path().to_string_lossy();

    let rendered = format!(
        "{roots:?} {discovery:?} {:?} {} {} {:?}",
        report,
        report.profiles()[0],
        report.issues()[0],
        BrowserProfileConfigError::InvalidRoot,
    );
    assert!(!rendered.contains(canary.as_ref()));
    assert!(rendered.contains("<redacted>"));
    assert!(report.profiles()[0].path().starts_with(fixture.path()));
}
