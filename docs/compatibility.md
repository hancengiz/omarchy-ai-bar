# Compatibility

The supported desktop is Omarchy 4.0.1 or newer on x86-64 Arch Linux with its
standard Quickshell-based shell. The package installs one Rust executable plus
QML, systemd, desktop metadata, icons, completions, documentation, and license
files. Omarchy, Qt, Quickshell, SQLite, D-Bus, and standard system libraries
remain system dependencies rather than being embedded in the executable.

The closed native registry contains all 69 providers in the pinned CodexBar
baseline. The complete provider and source list is maintained in the README.
Missing credentials are a visible setup state. Provider helpers are optional:
Codex can use `codex app-server` as a fallback, Grok uses the Grok Build CLI
billing RPC, and a small number of source-aware adapters use a bounded local
CLI or data store. Other providers use native HTTP adapters.

The bar plugin maps CodexBar's status item and popup to an Omarchy bar widget
and keyboard-capable panel. Omarchy's widget settings replace Apple preferences
for display mode, provider selection, used/remaining presentation, reset
visibility, unavailable providers, and warning threshold. systemd user units
replace login-item management, freedesktop notifications replace UserNotifications,
and AUR/pacman replace Sparkle updates.

The StatusNotifierItem fallback supplies a desktop indicator when no compatible
Omarchy display client is connected. Supported browser-session providers use a
Linux-native, bounded profile reader only as a lazy authentication fallback;
explicit environment or Secret Service credentials remain primary, browser
sessions are not copied into application configuration, and browser discovery
does not auto-enable a provider. Providers without a validated Linux browser
path continue to use an explicit environment or Secret Service value. QuickJS
plugins are local, explicitly evaluated, and have no network or host APIs in
version 0.3.0.

See [`unsupported-apple-semantics.md`](unsupported-apple-semantics.md) for the
two Apple-only behaviors that have no equivalent contract on Omarchy.
