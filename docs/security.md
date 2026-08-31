# Security model

Omarchy AI Bar runs provider work in one Rust executable and keeps QML as a
presentation-only client. The daemon and display endpoints are Unix sockets in
the user's private runtime directory. Both ends verify the peer UID, frames are
size bounded, and the display protocol requires a versioned handshake before
snapshots or actions are accepted.

Credentials remain in provider-owned files, environment variables, or the
desktop Secret Service. They are read only by the Rust backend and never sent
to QML. Public exports and diagnostics use redacted domain projections;
provider response bodies and secret values are excluded from errors and debug
output.

The Omarchy bridge installer validates a staged plugin, rejects links and
unsafe filesystem objects, installs atomically under the user's plugin folder,
and refuses to overwrite unrecognized or locally modified trees. Packages do
not edit home directories from pacman lifecycle hooks and never modify
`/usr/share/omarchy`.

Report security issues privately through the repository's GitHub security
advisory form. Do not include real credentials, cookies, provider response
bodies, or account identifiers in a report.
