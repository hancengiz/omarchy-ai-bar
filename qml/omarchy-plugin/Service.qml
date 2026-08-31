import QtQuick
import Quickshell
import Quickshell.Io
import "Protocol.js" as Protocol

Item {
    id: root

    property var shell: null
    property bool bridgeEnabled: true
    property bool connectionWanted: false
    property bool transportConnected: false
    property string connectionError: ""
    property var protocolState: Protocol.initialState()
    property double nextRequestId: 1
    property string sessionId: Protocol.newSessionId()
    property int readyGeneration: 0
    property var activePanelOwner: null
    property bool panelStateKnown: false
    property bool panelDesiredOpen: false
    property double panelStateRequestId: 0
    property int panelRetryCount: 0
    property string panelActionError: ""
    property var panelGeometrySources: []

    readonly property string runtimeDirectory: Quickshell.env("XDG_RUNTIME_DIR")
    readonly property string bridgeExecutable: Protocol.bridgeExecutablePath(Quickshell.env("OMARCHY_AI_BAR_EXECUTABLE"))
    readonly property string bridgeSocketOverrideRaw: Quickshell.env("OMARCHY_AI_BAR_DISPLAY_SOCKET")
    readonly property string bridgeSocketOverride: Protocol.bridgeSocketPath(bridgeSocketOverrideRaw)
    readonly property bool bridgeConfigurationValid: bridgeSocketOverrideRaw === "" || bridgeSocketOverride !== ""
    readonly property var bridgeCommand: Protocol.bridgeCommand(bridgeExecutable, bridgeSocketOverride)
    readonly property bool bridgeRunning: bridgeProcess.running
    readonly property bool compatible: protocolState.compatible === true
    readonly property string compatibilityFailure: protocolState.compatibilityFailure || ""
    readonly property bool hasRetainedSnapshot: protocolState.snapshot !== null
    readonly property bool hasLiveSnapshot: transportConnected && compatible && hasRetainedSnapshot
    readonly property int maxPanelRetries: 3
    readonly property bool panelRetryScheduled: panelRetryTimer.running
    readonly property var effectiveSnapshot: hasRetainedSnapshot ? protocolState.snapshot : syntheticSnapshot
    readonly property var currentProviderSnapshot: selectProviderSnapshot(effectiveSnapshot)
    readonly property var displaySample: sampleFrom(currentProviderSnapshot)
    readonly property var providerRows: rowsFrom(effectiveSnapshot)
    readonly property string providerId: displaySample && displaySample.scope ? String(displaySample.scope.provider || "ai") : "ai"
    readonly property string providerLabel: labelForProvider(providerId)
    readonly property real usedPercent: percentFrom(displaySample)
    readonly property string connectionStatus: {
        if (compatibilityFailure !== "")
            return "Incompatible";
        if (panelActionError !== "")
            return "Action failed";
        if (hasLiveSnapshot)
            return "Live";
        if (hasRetainedSnapshot)
            return "Stale";
        if (connectionError !== "")
            return "Offline";
        return "Preview";
    }

    readonly property var syntheticSnapshot: ({
            schema_version: 1,
            generated_at: "2026-08-29T00:00:00Z",
            snapshots: [
                {
                    state: "ready",
                    last_known_good: {
                        scope: {
                            provider: "codex",
                            instance: "preview",
                            account: "preview"
                        },
                        identity: {
                            account_label: "Preview account",
                            plan: "Pro"
                        },
                        fetched_at: "2026-08-29T00:00:00Z",
                        primary: {
                            usage: {
                                state: "known",
                                used_percent: 42
                            },
                            resets_at: "2026-08-29T05:00:00Z",
                            reset_description: "in 5 hours"
                        }
                    },
                    freshness: {
                        state: "fresh"
                    },
                    refresh: {
                        state: "idle"
                    },
                    error: null
                }
            ]
        })

    function registerPanelGeometrySource(source) {
        if (!source || panelGeometrySources.indexOf(source) !== -1)
            return;
        var next = panelGeometrySources.slice(0);
        next.push(source);
        panelGeometrySources = next;
    }

    function unregisterPanelGeometrySource(source) {
        panelGeometrySources = panelGeometrySources.filter(function (candidate) {
            return candidate && candidate !== source;
        });
    }

    function panelGeometryJson() {
        var values = [];
        for (var index = 0; index < panelGeometrySources.length; index++) {
            var source = panelGeometrySources[index];
            if (!source || typeof source.debugPanelGeometry !== "function")
                continue;
            var value = source.debugPanelGeometry();
            if (value)
                values.push(value);
        }
        values.sort(function (left, right) {
            return String(left.monitor || "").localeCompare(String(right.monitor || ""));
        });
        return JSON.stringify(values);
    }

    IpcHandler {
        target: "omarchy-ai-bar"

        function debugPanelGeometry(): string {
            return root.panelGeometryJson();
        }

        function refreshAll(): string {
            return root.refreshAll() ? "ok" : "unavailable";
        }

        function restartBridge(): string {
            if (!root.bridgeEnabled || root.runtimeDirectory === "" || !root.bridgeConfigurationValid)
                return "unavailable";
            root.scheduleReconnect("ipc_restart");
            return "ok";
        }

        function open(): string {
            return root.openFromIpc() ? "ok" : "unavailable";
        }

        function close(): string {
            return root.closeFromIpc() ? "ok" : "unavailable";
        }

        function toggle(): string {
            return root.toggleFromIpc() ? "ok" : "unavailable";
        }
    }

    function ipcPanelOwner() {
        if (activePanelOwner)
            return activePanelOwner;
        for (var index = 0; index < panelGeometrySources.length; index++) {
            var source = panelGeometrySources[index];
            if (source && typeof source.open === "function")
                return source;
        }
        return null;
    }

    function openFromIpc() {
        var owner = ipcPanelOwner();
        if (!owner || typeof owner.open !== "function")
            return false;
        owner.open();
        return true;
    }

    function closeFromIpc() {
        var owner = ipcPanelOwner();
        if (!owner || typeof owner.close !== "function")
            return false;
        owner.close();
        return true;
    }

    function toggleFromIpc() {
        var owner = ipcPanelOwner();
        if (!owner || typeof owner.togglePanel !== "function")
            return false;
        owner.togglePanel();
        return true;
    }

    function selectProviderSnapshot(envelope) {
        if (!envelope || !Array.isArray(envelope.snapshots))
            return null;
        for (var i = 0; i < envelope.snapshots.length; i++) {
            var candidate = envelope.snapshots[i];
            if (candidate && candidate.state === "ready" && candidate.last_known_good)
                return candidate;
        }
        return envelope.snapshots.length > 0 ? envelope.snapshots[0] : null;
    }

    function sampleFrom(providerSnapshot) {
        return providerSnapshot && providerSnapshot.state === "ready" ? providerSnapshot.last_known_good : null;
    }

    function rowsFrom(envelope) {
        if (!envelope || !Array.isArray(envelope.snapshots))
            return [];
        return envelope.snapshots.map(function (snapshot) {
            var sample = sampleFrom(snapshot);
            var provider = snapshot && snapshot.scope ? String(snapshot.scope.provider || "ai") : (sample && sample.scope ? String(sample.scope.provider || "ai") : "ai");
            var primary = sample && sample.primary ? sample.primary : null;
            var errorKind = snapshot && snapshot.error && snapshot.error.kind ? String(snapshot.error.kind) : "";
            var status = sample ? "Ready" : (errorKind === "missing_credential" ? "Sign in or configure a key" : (errorKind !== "" ? errorKind.replace(/_/g, " ") : "Loading"));
            return {
                provider: provider,
                label: labelForProvider(provider),
                percent: sample ? percentFrom(sample) : 0,
                ready: sample !== null,
                status: status,
                reset: primary && primary.reset_description ? String(primary.reset_description) : "",
                plan: sample && sample.identity && sample.identity.plan ? String(sample.identity.plan) : "",
                windows: sample ? windowsFrom(sample) : [],
                summary: sample ? summaryFrom(sample) : ""
            };
        });
    }

    function windowRow(title, window) {
        if (!window || !window.usage)
            return null;
        var known = window.usage.state === "known" && isFinite(Number(window.usage.used_percent));
        return {
            title: title,
            known: known,
            percent: known ? Math.max(0, Math.min(100, Number(window.usage.used_percent))) : 0,
            reset: window.reset_description ? String(window.reset_description) : ""
        };
    }

    function windowsFrom(sample) {
        var values = [];
        var primary = windowRow("Primary", sample.primary);
        var secondary = windowRow("Secondary", sample.secondary);
        var tertiary = windowRow("Tertiary", sample.tertiary);
        if (primary)
            values.push(primary);
        if (secondary)
            values.push(secondary);
        if (tertiary)
            values.push(tertiary);
        var extras = Array.isArray(sample.extra_windows) ? sample.extra_windows : [];
        for (var index = 0; index < extras.length; index++) {
            var extra = extras[index];
            var row = extra ? windowRow(String(extra.title || "Quota"), extra.window) : null;
            if (row)
                values.push(row);
        }
        return values;
    }

    function summaryFrom(sample) {
        var values = [];
        if (sample.credits && sample.credits.remaining !== null && sample.credits.remaining !== undefined)
            values.push(String(sample.credits.remaining) + " credits");
        if (sample.balance && sample.balance.amount !== undefined)
            values.push(String(sample.balance.amount) + (sample.balance.currency ? " " + String(sample.balance.currency) : ""));
        if (sample.cost && sample.cost.used && sample.cost.used.amount !== undefined)
            values.push(String(sample.cost.used.amount) + (sample.cost.used.currency ? " " + String(sample.cost.used.currency) : "") + " used");
        return values.join(" · ");
    }

    function percentFrom(sample) {
        var usage = sample && sample.primary ? sample.primary.usage : null;
        if (!usage || usage.state !== "known" || !isFinite(Number(usage.used_percent)))
            return 0;
        return Math.max(0, Math.min(100, Number(usage.used_percent)));
    }

    function labelForProvider(provider) {
        var labels = {
            abacus: "Abacus AI",
            aiand: "ai&",
            alibaba: "Alibaba Coding Plan",
            alibabatokenplan: "Alibaba Token Plan",
            amp: "Amp",
            antigravity: "Antigravity",
            augment: "Augment",
            azureopenai: "Azure OpenAI",
            bedrock: "AWS Bedrock",
            chutes: "Chutes",
            claude: "Claude",
            clawrouter: "ClawRouter",
            clinepass: "ClinePass",
            codebuff: "Codebuff",
            codex: "Codex",
            commandcode: "Command Code",
            copilot: "Copilot",
            crof: "Crof",
            cursor: "Cursor",
            deepgram: "Deepgram",
            deepinfra: "DeepInfra",
            deepseek: "DeepSeek",
            devin: "Devin",
            doubao: "Doubao",
            elevenlabs: "ElevenLabs",
            factory: "Droid",
            fireworks: "Fireworks",
            gemini: "Gemini",
            grok: "Grok",
            groq: "Groq",
            ibmbob: "IBM Bob",
            jetbrains: "JetBrains AI",
            kilo: "Kilo",
            kimi: "Kimi Code",
            kiro: "Kiro",
            litellm: "LiteLLM",
            llmproxy: "LLM Proxy",
            longcat: "LongCat",
            manus: "Manus",
            minimax: "MiniMax",
            mimo: "Xiaomi MiMo",
            mistral: "Mistral",
            moonshot: "Moonshot",
            neuralwatt: "Neuralwatt",
            notion: "Notion AI",
            ollama: "Ollama",
            openai: "OpenAI",
            opencode: "OpenCode",
            opencodego: "OpenCode Go",
            openrouter: "OpenRouter",
            perplexity: "Perplexity",
            poe: "Poe",
            qoder: "Qoder",
            qwencloud: "Qwen Cloud",
            sakana: "Sakana AI",
            stepfun: "StepFun",
            sub2api: "sub2api",
            synthetic: "Synthetic",
            t3chat: "T3 Chat",
            venice: "Venice",
            vertexai: "Vertex AI",
            warp: "Warp",
            wayfinder: "Wayfinder",
            windsurf: "Windsurf",
            xai: "xAI",
            zai: "z.ai Coding Plan",
            zed: "Zed",
            zenmux: "ZenMux",
            zoommate: "ZoomMate"
        };
        return labels[provider] || String(provider || "AI");
    }

    function allocateRequestId() {
        if (nextRequestId >= Protocol.MAX_EXACT_INTEGER) {
            sessionId = Protocol.newSessionId();
            nextRequestId = 1;
            protocolState = Protocol.resetRequests(protocolState);
            panelStateRequestId = 0;
            scheduleReconnect("request_id_space_exhausted");
            return 0;
        }
        var requestId = nextRequestId;
        nextRequestId += 1;
        return requestId;
    }

    function writeLine(line) {
        if (!connectionWanted || !transportConnected || !bridgeProcess.running || line === "")
            return false;
        bridgeProcess.write(line);
        return true;
    }

    function beginHandshake() {
        protocolState = Protocol.reconnectingState(protocolState);
        connectionError = "";
        transportConnected = true;
        handshakeTimer.restart();
        if (!writeLine(Protocol.clientHelloLine(sessionId)))
            scheduleReconnect("backend_unavailable");
    }

    function startConnection() {
        if (!bridgeEnabled || runtimeDirectory === "" || !bridgeConfigurationValid) {
            if (!bridgeConfigurationValid)
                connectionError = "invalid_bridge_configuration";
            return false;
        }
        connectionWanted = true;
        if (!bridgeProcess.running)
            bridgeProcess.running = true;
        return true;
    }

    function stopConnection() {
        transportConnected = false;
        handshakeTimer.stop();
        if (bridgeProcess.running) {
            bridgeProcess.running = false;
            forceStopTimer.restart();
        } else {
            forceStopTimer.stop();
        }
    }

    function scheduleReconnect(reason) {
        if (protocolState.phase === "incompatible")
            return;
        connectionError = reason;
        connectionWanted = false;
        stopConnection();
        if (bridgeEnabled && runtimeDirectory !== "")
            reconnectTimer.restart();
    }

    function handleProtocolLine(line) {
        var reduced = Protocol.reduceLine(protocolState, line);
        if (!reduced.accepted) {
            if (reduced.ackSequence > 0)
                writeLine(Protocol.snapshotAckLine(reduced.ackSequence));
            if (reduced.stale)
                return;
            if (reduced.fatal)
                scheduleReconnect(reduced.error || "protocol_error");
            return;
        }

        var previousStreamId = protocolState.streamId;
        var progressedRequestId = reduced.messageType === "action_progress" && reduced.state.lastActionProgress ? reduced.state.lastActionProgress.request_id : 0;
        var progressedState = reduced.messageType === "action_progress" && reduced.state.lastActionProgress ? reduced.state.lastActionProgress.state : "";
        var progressedCurrentPanel = progressedRequestId > 0 && progressedRequestId === panelStateRequestId;
        protocolState = reduced.state;
        if (protocolState.phase === "ready") {
            handshakeTimer.stop();
            if (reduced.messageType === "hello") {
                readyGeneration += 1;
                if (previousStreamId !== "" && previousStreamId !== protocolState.streamId) {
                    panelRetryCount = 0;
                    panelActionError = "";
                    panelRetryTimer.stop();
                }
                syncPanelState();
            }
            if (reduced.messageType === "action_progress") {
                if (progressedCurrentPanel && progressedState === "completed") {
                    panelRetryCount = 0;
                    panelActionError = "";
                    panelRetryTimer.stop();
                } else if (progressedCurrentPanel && ["failed", "cancelled"].indexOf(progressedState) !== -1) {
                    schedulePanelRetry(progressedState);
                } else if (Protocol.requestIsTerminal(protocolState, progressedRequestId) && panelStateKnown && panelStateRequestId <= 0 && !panelRetryTimer.running) {
                    syncPanelState();
                }
            }
        }
        if (protocolState.phase === "incompatible") {
            connectionError = "";
            connectionWanted = false;
            reconnectTimer.stop();
            stopConnection();
            return;
        }
        if (reduced.ackSequence > 0)
            writeLine(Protocol.snapshotAckLine(reduced.ackSequence));
    }

    function claimPanel(owner) {
        if (!owner)
            return false;
        if (activePanelOwner === owner)
            return true;
        var previous = activePanelOwner;
        activePanelOwner = owner;
        if (previous && typeof previous.closeForServiceSwitch === "function")
            previous.closeForServiceSwitch();
        return true;
    }

    function releasePanel(owner) {
        if (activePanelOwner === owner)
            activePanelOwner = null;
    }

    function reportPanelOpened() {
        return recordPanelState(true);
    }

    function reportPanelClosed() {
        return recordPanelState(false);
    }

    function ensurePanelStateRequest() {
        if (!panelStateKnown)
            return 0;
        if (panelStateRequestId > 0)
            return panelStateRequestId;
        var requestId = allocateRequestId();
        if (requestId <= 0)
            return 0;
        panelStateRequestId = requestId;
        protocolState = Protocol.registerRequest(protocolState, requestId);
        if (Protocol.requestProgressState(protocolState, requestId) === "") {
            panelStateRequestId = 0;
            connectionError = "too_many_actions";
            return 0;
        }
        if (connectionError === "too_many_actions")
            connectionError = "";
        return requestId;
    }

    function schedulePanelRetry(progressState) {
        if (panelRetryCount >= maxPanelRetries) {
            panelActionError = progressState === "cancelled" ? "panel_state_cancelled" : "panel_state_failed";
            panelRetryTimer.stop();
            return false;
        }
        panelRetryCount += 1;
        panelStateRequestId = 0;
        panelActionError = "";
        panelRetryTimer.restart();
        return true;
    }

    function runPanelRetry() {
        panelRetryTimer.stop();
        return syncPanelState();
    }

    function syncPanelState() {
        panelRetryTimer.stop();
        var requestId = ensurePanelStateRequest();
        if (requestId <= 0)
            return false;
        protocolState = Protocol.registerRequest(protocolState, requestId);
        if (Protocol.requestProgressState(protocolState, requestId) === "") {
            connectionError = "too_many_actions";
            return false;
        }
        if (!Protocol.hasCapability(protocolState, "runtime_actions"))
            return false;
        if (Protocol.hasCapability(protocolState, "action_progress")) {
            if (Protocol.requestIsCompleted(protocolState, requestId))
                return true;
            var progressState = Protocol.requestProgressState(protocolState, requestId);
            if (["failed", "cancelled"].indexOf(progressState) !== -1) {
                if (!schedulePanelRetry(progressState))
                    return false;
                panelRetryTimer.stop();
                requestId = ensurePanelStateRequest();
                if (requestId <= 0)
                    return false;
            }
        }
        var line = panelDesiredOpen ? Protocol.openPanelLine(requestId) : Protocol.closePanelLine(requestId);
        return writeLine(line);
    }

    function recordPanelState(open) {
        var desired = open === true;
        if (!panelStateKnown || panelDesiredOpen !== desired) {
            panelStateKnown = true;
            panelDesiredOpen = desired;
            panelStateRequestId = 0;
            panelRetryCount = 0;
            panelActionError = "";
            panelRetryTimer.stop();
        }
        syncPanelState();
        return true;
    }

    function refreshAll() {
        if (!Protocol.hasCapability(protocolState, "runtime_actions")) {
            connectionError = compatible ? "action_unavailable" : "backend_unavailable";
            return false;
        }
        var requestId = allocateRequestId();
        if (requestId <= 0)
            return false;
        protocolState = Protocol.registerRequest(protocolState, requestId);
        if (Protocol.requestProgressState(protocolState, requestId) === "") {
            connectionError = "too_many_actions";
            return false;
        }
        if (!writeLine(Protocol.refreshAllLine(requestId))) {
            connectionError = "backend_unavailable";
            if (!bridgeProcess.running)
                scheduleReconnect("backend_unavailable");
            return false;
        }
        return true;
    }

    Process {
        id: bridgeProcess
        command: root.bridgeCommand
        stdinEnabled: true
        running: false

        stdout: SplitParser {
            splitMarker: "\n"
            onRead: function (line) {
                if (root.connectionWanted && root.transportConnected && bridgeProcess.running)
                    root.handleProtocolLine(line);
            }
        }

        stderr: SplitParser {
            splitMarker: "\n"
            onRead: function (line) {
            // Drain the tracked bridge's generic diagnostics. Never expose
            // child stderr as UI or protocol data.
            }
        }

        onStarted: root.beginHandshake()
        onRunningChanged: {
            if (running)
                return;
            root.transportConnected = false;
            forceStopTimer.stop();
            if (root.connectionWanted && root.protocolState.phase !== "incompatible")
                root.scheduleReconnect("backend_unavailable");
        }
    }

    Timer {
        id: handshakeTimer
        interval: 5000
        repeat: false
        onTriggered: root.scheduleReconnect("handshake_timeout")
    }

    Timer {
        id: reconnectTimer
        interval: 1000
        repeat: false
        onTriggered: root.startConnection()
    }

    Timer {
        id: forceStopTimer
        interval: 750
        repeat: false
        onTriggered: {
            if (bridgeProcess.running)
                bridgeProcess.signal(9);
        }
    }

    Timer {
        id: panelRetryTimer
        interval: Math.min(4000, 250 * Math.pow(2, Math.max(0, root.panelRetryCount - 1)))
        repeat: false
        onTriggered: root.runPanelRetry()
    }

    Component.onCompleted: startConnection()
    Component.onDestruction: {
        connectionWanted = false;
        reconnectTimer.stop();
        handshakeTimer.stop();
        forceStopTimer.stop();
        panelRetryTimer.stop();
        if (bridgeProcess.running)
            bridgeProcess.running = false;
    }
}
