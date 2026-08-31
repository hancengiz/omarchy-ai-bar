# Unsupported Apple-only semantics

Only two baseline behaviors are intentionally unsupported:

1. Encrypted secret synchronization through Apple platform keychain/app-group
   facilities. Fleet aggregation may synchronize redacted usage snapshots, but
   never credentials.
2. WidgetKit timeline and Apple app-group host semantics. Omarchy uses a live
   Quickshell bar widget backed by the Rust daemon; it does not claim WidgetKit
   scheduling or app-group behavior.

Other Apple framework integrations are mapped to Linux/Omarchy facilities as
documented in [`compatibility.md`](compatibility.md).
