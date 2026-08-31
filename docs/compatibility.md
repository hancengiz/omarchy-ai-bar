# Compatibility

The supported desktop is Omarchy 4.0.1 or newer on x86-64 Arch Linux with its
standard Quickshell-based shell. The package installs one Rust executable plus
QML, systemd, desktop metadata, icons, completions, documentation, and license
files. Omarchy, Qt, Quickshell, SQLite, D-Bus, and standard system libraries
remain system dependencies rather than being embedded in the executable.

The current end-to-end provider set is Codex, Claude, Grok, z.ai Coding Plan,
OpenAI, Azure OpenAI, Fireworks, Moonshot, OpenRouter, Deepgram, Chutes,
Neuralwatt, IBM Bob, xAI, LiteLLM, LLM Proxy, sub2api, Synthetic, DeepInfra,
Venice, Poe, ZenMux, ai&, Warp, ClinePass, ElevenLabs, AWS Bedrock, Vertex AI,
JetBrains AI, Wayfinder, ClawRouter, Crof, Codebuff, Amp, Doubao, Kilo, Kiro,
Alibaba Token Plan, Abacus, Alibaba Coding Plan, Command Code, Devin, LongCat,
Manus, MiniMax, Mistral, Notion AI, OpenCode, Perplexity, Qoder, Qwen Cloud,
Sakana, StepFun, T3 Chat, ZoomMate, GitHub Copilot, Kimi, and Xiaomi MiMo.
Missing credentials are a visible setup state. Provider helpers are optional:
Codex can use
`codex app-server` as a fallback and Grok requires the Grok Build CLI billing
RPC; the other providers use native HTTP adapters.

The bar plugin maps CodexBar's status item and popup to an Omarchy bar widget
and keyboard-capable panel. Omarchy's widget settings replace Apple preferences
for display mode, provider selection, used/remaining presentation, reset
visibility, unavailable providers, and warning threshold. systemd user units
replace login-item management, freedesktop notifications replace UserNotifications,
and AUR/pacman replace Sparkle updates.

See [`unsupported-apple-semantics.md`](unsupported-apple-semantics.md) for the
two Apple-only behaviors that have no equivalent contract on Omarchy.
