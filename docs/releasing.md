# Releasing

1. Run the full Rust, QML, policy, parity, package-layout, and secret-canary
   gates from CI.
2. Build and verify the deterministic direct archive:

   ```sh
   scripts/build-release.sh 0.3.0
   scripts/verify-archive.sh dist/omarchy-ai-bar-0.3.0-linux-x86_64.tar.gz
   ```

3. Tag the exact audited commit as `v0.3.0`. The release workflow builds the
   archive again and attaches it and its checksum to the GitHub release.
4. Replace the PKGBUILD source checksum with the SHA-256 of GitHub's tag
   archive, regenerate `.SRCINFO`, and test with `makepkg --cleanbuild`.
5. Generate a SHA-256 file for the resulting `.pkg.tar.zst` and attach both to
   the GitHub release. Commit and push the finalized PKGBUILD checksum.
6. If AUR publishing access is available, copy only `PKGBUILD`, `.SRCINFO`,
   `omarchy-ai-bar.install`, and the repository `LICENSE` to the AUR Git
   repository and push a reviewable commit.

The repository PKGBUILD may temporarily contain the previous release checksum
in the version-bump commit because a GitHub tag archive does not exist before
the tag. Do not build or publish that intermediate package state. The checksum
update after tagging is the publishable package source.

For later upstream ports, run `scripts/upstream-diff.sh` against a current
CodexBar checkout before changing the pinned parity baseline. GitHub Releases
and package managers are the update authorities; the application must not
download or replace itself.
