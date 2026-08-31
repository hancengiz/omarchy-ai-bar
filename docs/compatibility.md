# Compatibility

The supported desktop is Omarchy 4.0.1 or newer on x86-64 Arch Linux with its
standard Quickshell-based shell. The package installs one Rust executable plus
QML, systemd, desktop metadata, icons, completions, documentation, and license
files. Omarchy, Qt, Quickshell, SQLite, D-Bus, and standard system libraries
remain system dependencies rather than being embedded in the executable.

The current end-to-end provider set is Codex, Claude, Grok, and z.ai Coding
Plan. Missing credentials are a visible setup state. Provider helpers are
optional: Codex can use `codex app-server` as a fallback and Grok requires the
Grok Build CLI billing RPC; Claude and z.ai have native HTTP adapters.

The bar plugin maps CodexBar's status item and popup to an Omarchy bar widget
and keyboard-capable panel. Omarchy's widget settings replace Apple preferences
for display mode, provider selection, used/remaining presentation, reset
visibility, unavailable providers, and warning threshold. systemd user units
replace login-item management, freedesktop notifications replace UserNotifications,
and AUR/pacman replace Sparkle updates.

See [`unsupported-apple-semantics.md`](unsupported-apple-semantics.md) for the
two Apple-only behaviors that have no equivalent contract on Omarchy.
