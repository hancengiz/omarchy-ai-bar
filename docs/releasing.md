# Releasing

1. Run the full Rust, QML, policy, parity, package-layout, and secret-canary
   gates from CI.
2. Build and verify the deterministic direct archive:

   ```sh
   scripts/build-release.sh 0.4.0
   scripts/verify-archive.sh dist/omarchy-ai-bar-0.4.0-linux-x86_64.tar.gz
   ```

3. Tag the exact audited commit as `v0.4.0`. The release workflow builds and
   verifies the direct archive and Arch package in separate jobs. A final job
   publishes both artifacts and their adjacent checksums with GitHub's built-in
   workflow token; release files are never uploaded manually through the web
   interface.
4. Replace the repository PKGBUILD source checksum with the SHA-256 of GitHub's
   tag archive, regenerate `.SRCINFO`, test with `makepkg --cleanbuild`, and
   commit the finalized recipe. The release workflow independently derives and
   verifies the tag checksum before its package build.
5. Publish to the AUR by copying only `PKGBUILD`, `.SRCINFO`,
   `omarchy-ai-bar.install`, and the repository `LICENSE` to the AUR Git
   repository and pushing a reviewable commit. The recipe must stay
   installable on plain Arch: nothing may depend on the `omarchy` package
   or call its CLI from `check()`, because Omarchy is installed as a
   system and is not packaged anywhere. AUR account registration has been
   closed since the mid-2026 malicious-package incidents (aurweb v6.5.0
   re-enabled push and adoption for existing accounts only). Without an
   account, request an upload by an existing maintainer on the
   `aur-general` list or in `#archlinux-aur` on Libera Chat, then adopt or
   co-maintain the package once registration reopens.

To rebuild an existing release tag, run the `Release` workflow manually with
the exact tag name. The same jobs rebuild and replace all four release assets;
the browser does not receive local files.

The repository PKGBUILD may temporarily contain the previous release checksum
in the version-bump commit because a GitHub tag archive does not exist before
the tag. Do not build or publish that intermediate package state. The checksum
update after tagging is the publishable package source.

For later upstream ports, run `scripts/upstream-diff.sh` against a current
CodexBar checkout before changing the pinned parity baseline. GitHub Releases
and package managers are the update authorities; the application must not
download or replace itself.
