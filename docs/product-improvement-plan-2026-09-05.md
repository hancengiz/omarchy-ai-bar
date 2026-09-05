# Product improvement plan — 5 September 2026

The next product milestone should make Codex and Claude complete, understandable daily tools. Provider-count parity is already a foundation; it is a poor release criterion for the experience the user actually has.

The core product promise should be: **know which account you are looking at, how much capacity remains, when it resets, and what your local activity represents. Every missing number must have an explanation.**

## Audit scope and evidence

- Omarchy AI Bar reviewed at `3239fbc`, with a clean working tree before this document. The installed daemon is active and reports version `0.4.0`; this does not establish that its binary and installed QML match every current source change.
- Fast-forwarded `/home/hancengiz/code/CodexBar` from `1680b4ed5bca69f167d388ed17a5b2c36dd05d1f` to `eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a`. Its checkout remains clean. This is 116 commits and 466 changed files beyond our pinned baseline. Latest HEAD starts 0.56.7 development; its changelog identifies 0.56.6 as the latest released version.
- Inspected provider implementations/settings, account construction, cost readers, runtime refresh, QML presentation, notification delivery, storage, and parity records. Compared these with current CodexBar provider code, account behavior, cost/history documentation, settings, and changelog.
- The three referenced screenshot files were unavailable. This is a source and local-file-metadata audit, not a pixel comparison or a reproduction of the exact screenshots. No provider login, credential mutation, account switching, or live usage probe was performed.
- Current ledger: 69 provider records, of which 58 are `in-progress` and 11 `planned`; 37 feature records, of which 27 are `planned`, 8 `in-progress`, and 2 `unsupported-approved`. These are tracking states, not measured percentages of working functionality. Several records lag existing implementation.

## Why one Codex account has a graph and another does not

The strongest explanation is a difference in local history, combined with an unexplained empty state.

1. Native Codex and managed Codex accounts each have a separate quota source and local history root. Managed history is rooted under the application's `codex/managed-accounts/<id>` directory ([construction](../crates/app/src/provider_bootstrap.rs)).
2. The local metadata check found 219 JSONL session files in the ambient Codex home and one managed home with no `sessions` directory. This count is not a count of usable days or priced requests; file contents were not inspected for this check.
3. The [Codex history scanner](../crates/providers/src/providers/codex_cost.rs) returns no history when it finds no usable local rollout data. Successfully signing in to a managed account does not download its activity history.
4. [Service.qml](../qml/omarchy-plugin/Service.qml) returns a null chart without daily buckets; [UsageView.qml](../qml/omarchy-plugin/UsageView.qml) hides the entire cost section without cost statistics, and [InlineChart.qml](../qml/omarchy-plugin/InlineChart.qml) hides itself without points. There is no explanation beside the missing graph.
5. CodexBar also defaults managed accounts to their own history, but offers an opt-in **Local session cost estimates** mode that uses the machine's ambient history independently of the selected quota account. Our descriptor includes that control but marks it unavailable.

This supports the reported symptom if “graph” means the daily cost/token chart. It does not establish the cause of a missing quota bar or the exact ordering of the accounts in the lost screenshot.

**Product decision:** keep account-specific history as the default. Offer machine-local activity as a clearly labelled alternative. Never silently copy native history onto another account or imply that local estimates are that account's invoice. A signed-in account with no local sessions should still have a useful card.

## Comparison with the current benchmark

| Experience | Omarchy AI Bar today | CodexBar benchmark / improvement needed | Priority |
| --- | --- | --- | --- |
| Account identity | Managed Codex login, display selection, removal, independent refresh, and banked reset inventory work | Add clear display-vs-CLI selection labels, workspace selection, and same-email workspace distinction | P0/P1 |
| Missing history | Cost section disappears | Explicit empty, scanning, unavailable, partial, and stale states; configurable local-history scope | P0 |
| Codex options | 9 descriptors; source, Spark visibility, and external OAuth consent are runtime-backed | Local estimates, historical tracking, web extras, cookie policy, and battery saver still unavailable | P0/P1 |
| Claude options | 11 descriptors; only the usage-source control is runtime-backed, with Auto/OAuth/CLI choices | Web source, Admin API, account management, Daily Routines filtering, and `claude-swap` need real runtime paths | P1 |
| Claude usage detail | OAuth normalization already handles session/weekly, scoped limits, routines, and extra usage | Avoid treating these as wholly missing; complete display controls, source fidelity, web balances, and recovery | P0/P1 |
| Local cost collection | Separate Codex/Claude readers, 30-day windows, 15-minute in-memory success caches | Configurable windows/time zone, persistent incremental work, richer coverage, additional source roots and deduplication | P1 |
| Chart interaction | Basic inline bars; cost chosen automatically when any amount is available | Explicit Tokens/Cost selection, exact values, continuous dates, model/token breakdowns, coverage labels | P0/P1 |
| Pricing | Hard-coded provider tables | Versioned price coverage and repricing. Current Codex table lacks a model present in the latest benchmark's pricing update (`gpt-6-astra`) | P0/P1 |
| Historical quota/pace | Current quota and elapsed-window pace; bounded history storage foundation | Account/workspace-scoped persistence, restoration, and evidence-based personalized pace | P1 |
| Notifications | QML widget emits a global-threshold `notify-send` warning | Daemon-owned account/window rules, reset/depletion/expiry events, persistent deduplication | P1 |
| Product settings | Working basic display/layout and warning controls, typed flagship forms | Functional grouping, visible dependencies, complete refresh/history controls, Linux-appropriate credential settings | P0/P1 |
| Wider product | Broad provider adapters, sessions/CLI/server/hooks/plugin foundations | Verify end-to-end flows; add user-facing configuration, diagnostics, storage and export incrementally | P2 |

The macOS Keychain policy toggles are platform-specific controls, not three missing Linux features. Replace them with accurate Linux credential-source/consent information. A desktop widget concept can have a Quickshell equivalent; native WidgetKit hosting itself remains outside scope.

## Issues beyond the screenshots

**Unknown cost can look like zero.** `costChartFrom()` selects cost if any day has an amount, then converts each missing amount with `Number(raw || 0)`. A partially priced history can therefore draw an unknown day as zero. The scanner already has pricing-coverage information, but the chart does not explain it. Prioritize this as data correctness, not polish.

**Local history is coupled to successful quota acquisition.** The runtime starts optional history work after a required usage sample succeeds. Consequently, a fresh Codex/Claude quota failure can prevent discovering otherwise readable local logs. Existing retained data may remain visible, but that is different from an independent local-cost mode. The new local mode needs its own scheduling and state.

**History controls require a storage contract.** The current `history_records` schema contains provider, metric, timestamp, and value, without an explicit account/workspace dimension. No production history-store wiring was found in the reviewed application paths. Do not enable “Historical tracking” merely by accepting the config value: define ownership, persistence, migration, retention, and delete semantics first.

**Warnings need account-level delivery.** `BarWidget.qml` deduplicates by provider and holds one pending notification title. Multiple simultaneous crossings can be marked warned while only one is selected for delivery. Moving notification ownership into the daemon should include a real queue and account/window/reset-boundary identity, plus tests for simultaneous crossings.

**The documentation cannot currently serve as the acceptance checklist.** `docs/codexbar-parity.md` describes managed Codex accounts as implemented in one section and not yet ported in another. It also lists display filters as unavailable despite Spark filtering being implemented. The settings About text still describes packaging as unpublished. Reconcile these statements with executable evidence before adding further parity claims.

**The upstream delta includes correctness work we should explicitly review.** Recent changes address selected-workspace ownership, suspicious weekly resets, exhausted-quota selection, unknown/zero credits, partial cost scans, source-specific Claude recovery, and same-email account labels. They are more valuable than importing every new visual option. The local Codex “Workspaces” project inspector described upstream is still a debug-gated scaffold; do not advertise it as a mature released benchmark feature or confuse it with account workspace selection.

## Proposed delivery backlog

Effort estimates are relative: S = a focused change; M = several connected layers; L = a feature spanning storage/runtime/UI. They are sequencing aids, not calendar commitments.

| ID | Deliverable and ownership in code | Depends on | Effort | Acceptance criterion |
| --- | --- | --- | --- | --- |
| P0-1 | Explicit history status and scope in domain/display payload, `Service.qml`, `UsageView.qml`, and `InlineChart.qml` | None | M | Native history plus an empty managed home shows a graph for one and an explanatory state for the other. Empty, disabled, scanning, partial, stale, and failed states are distinguishable. |
| P0-2 | Make Codex local-session estimates functional through descriptor, config, bootstrap, independent history refresh, and UI | P0-1 | L | Changing quota account does not relabel machine activity as account activity. Local history loads with quota auth unavailable. Saved selection survives restart; obsolete scope results cannot publish. |
| P0-3 | Correct cost chart semantics: preserve unknowns, add Tokens/Cost choice, coverage and date labels | P0-1 | M | Mixed priced/unpriced days never imply a known zero; tokens remain inspectable; confirmed empty days have explicit coverage; exact values are accessible by pointer and keyboard. |
| P0-4 | Settings and account clarity in `ProviderDetail.qml`, `AppSettings.qml`, typed descriptors, docs | None | M | Normal settings expose working Linux controls. Unsupported platform items disappear from ordinary forms; genuinely pending features appear in a compact explanation. “Show in bar” and “Use in Codex CLI” cannot be confused. |
| P1-1 | Persistent incremental local-cost pipeline; configurable range/time zone; versioned pricing; source-root expansion | P0-1, P0-2 | L | Same-scope last-good totals survive restart and partial scans. Unchanged files avoid full rescans. Append, rotation, archive, duplicate/fork, unknown-price, and midnight cases preserve correct totals. |
| P1-2 | Historical tracking and account/workspace-aware quota restoration; trustworthy pace | P0-1, storage design | L | Each account/window resumes its own history after restart; disabling collection has defined retention behavior; explicit deletion works; estimated quotas do not produce unjustified forecasts. |
| P1-3 | Complete Claude display/source experience, starting with Daily Routines filtering and source fidelity, then Web/manual cookies | P0-4 | M/L | OAuth/CLI remain usable independently; routine filter changes presentation only. Web failures preserve valid base usage and explain authentication versus network challenges. |
| P1-4 | Claude accounts: native app-owned token accounts, then optional `cswap` adapter | P1-3 and shared account model | L | Two accounts retain independent identity, refresh, history state, and errors. `cswap` runs bounded fixed commands only when enabled; explicit switching validates the requested slot and failure keeps last-good data. |
| P1-5 | Codex workspace selection and optional native CLI promotion | P0-4 and account ownership audit | L | Same-email workspaces remain distinct; quota, resets, history and late results honor selection. Promotion is a separate explicit action with recoverable state, never a side effect of display selection. |
| P1-6 | Codex OpenAI web extras and Linux cookie policy, followed by power-aware cadence | Account matching from P1-5 | L | Extras match the selected account/workspace, have independent freshness and deadlines, and cannot block or overwrite base quota. Cookie Off performs no discovery. |
| P1-7 | Daemon-backed refresh and notification settings | Shared account/window identity | M/L | Warnings work with popup closed and without a connected widget, queue simultaneous crossings, suppress duplicates across restart, and support per-account/window thresholds and reset-credit expiry. |
| P2-1 | Claude Admin API spend with organization selection and explicit scope | P1-3, shared cost view | M/L | Organization spend is labelled separately from Claude Code subscription quota; keys use Secret Service; missing admin privileges never masquerade as zero spend. |
| P2-2 | Usage & Spend view, model/token breakdowns, date navigation, privacy-aware export/storage tools | P1-1 | L | Totals reconcile with visible filters and source scope; estimates and billed spend are distinct; export and deletion respect documented privacy semantics. |
| P2-3 | Finish other high-use providers, sessions/hooks/plugin controls, ordering, keyboard/accessibility and scaling | Flagship acceptance suite | Iterative | Each shipped flow has working configuration, runtime behavior, recovery and a UI proof. Audit the remaining provider inventory in batches instead of declaring blanket parity. |

### First release: clarity and useful history

Ship P0-1 through P0-4 together, with a focused price-coverage audit. The user should immediately understand the missing graph, be able to choose machine-local estimates, inspect tokens when costs are incomplete, and configure Codex/Claude without a wall of disabled controls.

The proposed card hierarchy is provider/account/workspace and freshness first; quota and reset windows second; optional balances third; explicitly scoped local activity fourth. Use text such as **“No local sessions for this account”**, with **“Show this machine's activity”** as an intentional choice. When enabled, label that section **“This machine · estimated activity”**. A missing source should explain itself in the place where its chart would appear.

Group settings into Account, Usage source, History & costs, Display, and Advanced. Keep support status in the help/details surface while unfinished behavior is being implemented; moving a disabled control is not feature completion.

### Second release: complete daily Codex and Claude workflows

Deliver persistent history, Claude display/web/account paths, account workspace correctness, and reliable warnings. Sequence local-cost infrastructure before increasing history ranges or adding a dashboard. Complete identity matching before web enrichment or native CLI promotion. Add Codex extras with their own failure and power policies.

### Third release: analysis and broader parity

Add Admin API spend, Usage & Spend, storage/export, and the next providers by observed usage. Do not block first-release usability on fleet sync, Apple-specific semantics, a projects inspector, or supporting every benchmark preference.

## Verification and release gates

1. Create a deterministic fixture matrix: native plus empty managed account; two populated accounts; same-email/different-workspace accounts; stale quota with readable logs; missing credentials; rate limit; partial scan; no pricing; genuine zero; scoped Claude quotas; simultaneous notification crossings.
2. Extend existing provider tests, `crates/app/tests/codex_accounts.rs`, runtime tests, display E2E tests, and QML protocol tests at the relevant seam. Validate saved option → adapter/scanner behavior → display result, rather than merely checking descriptor text.
3. Render fixture-driven QML proofs with the installed build identified. Check account switching, chart selection, scrolling, long identities, keyboard focus, empty states, and fractional scale. The unavailable screenshots mean this visual verification is still outstanding.
4. Keep quota publication independent of cost/web latency; test cancellation and late results after account/settings changes. Confirm manual history refresh semantics and ensure disabling a feature stops its work.
5. For scanner changes, benchmark cold scan, no-change refresh, append-only refresh, cancellation, and constrained catch-up using synthetic logs. Record before/after time, bytes read, and peak memory; set budgets from those measurements before release.
6. Reconcile the parity ledger with evidence. Preserve the original baseline until the new inventory and tests are reviewed; record this audit's comparison revision separately. Use `scripts/upstream-diff.sh` to review drift, and the strict parity gate only for an actual complete-parity claim. Passing structural ledger tests is not evidence that all product workflows work.

Release acceptance should be concrete: no unexplained missing charts; no unknown-as-zero data; no cross-account attribution; no enabled setting that the runtime ignores; both flagship providers have working recovery paths. These are proposed gates, not claims that the current implementation passes them.

## Reference map

Local implementation references:

- [Typed provider settings and availability](../crates/providers/src/settings_descriptor.rs)
- [Account/runtime construction](../crates/app/src/provider_bootstrap.rs), [managed accounts](../crates/app/src/codex_accounts.rs), [cost refresh/cache](../crates/app/src/provider_refresh.rs)
- [Runtime required/optional work](../crates/runtime/src/actor.rs), [history schema](../crates/storage/src/history.rs)
- [Codex cost reader](../crates/providers/src/providers/codex_cost.rs), [Claude cost reader](../crates/providers/src/providers/claude_cost.rs), [Claude normalization](../crates/providers/src/providers/claude.rs)
- [Display projection](../qml/omarchy-plugin/Service.qml), [usage cards](../qml/omarchy-plugin/UsageView.qml), [charts](../qml/omarchy-plugin/InlineChart.qml), [warnings](../qml/omarchy-plugin/BarWidget.qml)

Benchmark references are pinned to the pulled revision:

- [Codex account, source and cost behavior](https://github.com/steipete/CodexBar/blob/eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a/docs/codex.md)
- [Claude sources and multi-account behavior](https://github.com/steipete/CodexBar/blob/eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a/docs/claude.md)
- [Codex settings implementation](https://github.com/steipete/CodexBar/blob/eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a/Sources/CodexBar/Providers/Codex/CodexProviderImplementation.swift)
- [Claude settings implementation](https://github.com/steipete/CodexBar/blob/eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a/Sources/CodexBar/Providers/Claude/ClaudeProviderImplementation.swift)
- [Recent fixes](https://github.com/steipete/CodexBar/blob/eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a/CHANGELOG.md)
- [Project Workspaces scope and scaffold limitations](https://github.com/steipete/CodexBar/blob/eecb7e3a3ff2d31993dcad1f78a62467e44c0b5a/docs/codex-workspaces.md)

This change records the audit and delivery plan only. No product behavior was changed and no application test suite was run for this documentation-only work.
