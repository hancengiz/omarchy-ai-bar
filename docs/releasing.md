# Releasing

1. Run the full Rust, QML, policy, parity, package-layout, and secret-canary
   gates from CI.
2. Build and verify the deterministic direct archive:

   ```sh
   scripts/build-release.sh 0.2.0
   scripts/verify-archive.sh dist/omarchy-ai-bar-0.2.0-linux-x86_64.tar.gz
   ```

3. Tag the exact audited commit as `v0.2.0`. The release workflow builds the
   archive again and attaches it and its checksum to the GitHub release.
4. Replace the PKGBUILD source checksum with the SHA-256 of GitHub's tag
   archive, regenerate `.SRCINFO`, and test with `makepkg --cleanbuild`.
5. Copy only `PKGBUILD`, `.SRCINFO`, and `omarchy-ai-bar.install` to the AUR
   Git repository and push a signed reviewable commit.

The repository PKGBUILD may temporarily contain the previous release checksum
in the version-bump commit because a GitHub tag archive does not exist before
the tag. Do not copy that intermediate state to AUR. The checksum-update commit
after tagging is the publishable package source.

For later upstream ports, run `scripts/upstream-diff.sh` against a current
CodexBar checkout before changing the pinned parity baseline. AUR/pacman is the
only update authority; the application must not download or replace itself.
