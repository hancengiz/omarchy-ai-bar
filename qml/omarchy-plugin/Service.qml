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
    property var providerEnabledOverrides: ({})
    property var providerOrder: []
    property var providerEndpointOverrides: ({})
    property var providerOptionsOverrides: ({})
    property var providerAccountPresence: ({})
    property var providerAccountRoutes: ({})
    property var activeProviderAccounts: ({})
    property var providerSettingsDescriptors: ({})
    property bool providerSettingsDescriptorsLoaded: false
    property var credentialSlotStates: ({})
    property var credentialStatusQueue: []
    property string activeCredentialStatusKey: ""
    property bool providerConfigLoaded: false
    property bool providerConfigReloadPending: false
    property double resetInventoryNow: Date.now()
    property bool providerConfigBusy: false
    property string providerConfigResult: ""
    property string pendingCredential: ""
    property bool copilotAppSessionConfigured: false
    property bool copilotSessionStatusLoaded: false

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
    readonly property var effectiveSnapshot: hasRetainedSnapshot ? protocolState.snapshot : emptySnapshot
    readonly property var currentProviderSnapshot: selectProviderSnapshot(effectiveSnapshot)
    readonly property var displaySample: sampleFrom(currentProviderSnapshot)
    readonly property var providerRows: rowsFrom(effectiveSnapshot)
    readonly property var configuredProviderRows: providerRows.filter(function (row) {
        return row && row.configured && row.enabled;
    })
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
        return bridgeRunning || transportConnected ? "Waiting for data" : "Offline";
    }

    readonly property var emptySnapshot: ({
            schema_version: 1,
            generated_at: "1970-01-01T00:00:00Z",
            snapshots: []
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

        function debugProviderState(): string {
            return JSON.stringify({
                configured: root.configuredProviderRows.map(function (row) {
                    return row.provider;
                }),
                enabled: root.providerRows.filter(function (row) {
                    return row.enabled;
                }).map(function (row) {
                    return row.provider;
                }),
                rows: root.providerRows.filter(function (row) {
                    return row.enabled;
                }).map(function (row) {
                    return {
                        provider: row.provider,
                        configured: row.configured,
                        detected: row.detected,
                        ready: row.ready,
                        windows: row.windows,
                        detailSectionCount: row.detailSections.length
                    };
                }),
                configLoaded: root.providerConfigLoaded
            });
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

        function settings(): string {
            return root.openSettingsFromIpc("") ? "ok" : "unavailable";
        }

        function providerSettings(provider: string): string {
            return root.openSettingsFromIpc(provider) ? "ok" : "unavailable";
        }

        function providerCatalog(): string {
            return root.openProviderCatalogFromIpc() ? "ok" : "unavailable";
        }

        function appSettings(pane: string): string {
            return root.openAppSettingsFromIpc(pane) ? "ok" : "unavailable";
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

    function openSettingsFromIpc(provider) {
        var value = String(provider || "");
        if (value !== "" && providerIds().indexOf(value) === -1)
            return false;
        var owner = ipcPanelOwner();
        if (!owner || typeof owner.openProviderSettings !== "function")
            return false;
        owner.openProviderSettings(value);
        return true;
    }

    function openProviderCatalogFromIpc() {
        var owner = ipcPanelOwner();
        if (!owner || typeof owner.openProviderCatalog !== "function")
            return false;
        owner.openProviderCatalog();
        return true;
    }

    function openAppSettingsFromIpc(pane) {
        var value = String(pane || "");
        if (["display", "notifications", "advanced", "about"].indexOf(value) === -1)
            return false;
        var owner = ipcPanelOwner();
        if (!owner || typeof owner.openAppSettings !== "function")
            return false;
        owner.openAppSettings(value);
        return true;
    }

    function selectProviderSnapshot(envelope) {
        if (!envelope || !Array.isArray(envelope.snapshots))
            return null;
        for (var i = 0; i < envelope.snapshots.length; i++) {
            var candidate = envelope.snapshots[i];
            var provider = providerIdFromSnapshot(candidate);
            if (provider === "codex" && accountIdFromSnapshot(candidate) !== (activeProviderAccounts.codex || "ambient"))
                continue;
            if (candidate && candidate.state === "ready" && candidate.last_known_good && isProviderEnabled(provider, true))
                return candidate;
        }
        for (var fallbackIndex = 0; fallbackIndex < envelope.snapshots.length; fallbackIndex++) {
            var fallback = envelope.snapshots[fallbackIndex];
            if (providerIdFromSnapshot(fallback) === "codex" && accountIdFromSnapshot(fallback) !== (activeProviderAccounts.codex || "ambient"))
                continue;
            if (isProviderEnabled(providerIdFromSnapshot(fallback), true))
                return fallback;
        }
        return null;
    }

    function subscriptionRows(providerRow, layout) {
        if (!providerRow || providerRow.provider !== "codex" || layout !== "List")
            return providerRow ? [providerRow] : [];
        return codexAccountChoices().map(function (account) {
            var rows = rowsFrom(effectiveSnapshot, {
                codex: account.id
            });
            var row = rows.filter(function (candidate) {
                return candidate.provider === "codex";
            })[0];
            row.account = row.account || account.email || (account.ambient ? "Native account" : account.id);
            row.subscriptionId = account.id;
            return row;
        });
    }

    function providerIdFromSnapshot(snapshot) {
        if (snapshot && snapshot.scope && snapshot.scope.provider)
            return String(snapshot.scope.provider);
        if (snapshot && snapshot.last_known_good && snapshot.last_known_good.scope)
            return String(snapshot.last_known_good.scope.provider || "");
        return "";
    }

    function accountIdFromSnapshot(snapshot) {
        if (snapshot && snapshot.scope && snapshot.scope.account)
            return String(snapshot.scope.account);
        if (snapshot && snapshot.last_known_good && snapshot.last_known_good.scope)
            return String(snapshot.last_known_good.scope.account || "");
        return "";
    }

    function sampleFrom(providerSnapshot) {
        return providerSnapshot && providerSnapshot.state === "ready" ? providerSnapshot.last_known_good : null;
    }

    function rowsFrom(envelope, accountOverrides) {
        var snapshots = envelope && Array.isArray(envelope.snapshots) ? envelope.snapshots : [];
        var indexed = {};
        for (var snapshotIndex = 0; snapshotIndex < snapshots.length; snapshotIndex++) {
            var indexedProvider = providerIdFromSnapshot(snapshots[snapshotIndex]);
            if (indexedProvider !== "") {
                if (!Array.isArray(indexed[indexedProvider]))
                    indexed[indexedProvider] = [];
                indexed[indexedProvider].push(snapshots[snapshotIndex]);
            }
        }
        return providerIds().map(function (provider) {
            var candidates = indexed[provider] || [];
            var activeAccount = (accountOverrides || activeProviderAccounts)[provider] || "ambient";
            var snapshot = null;
            for (var candidateIndex = 0; candidateIndex < candidates.length; candidateIndex++) {
                if (accountIdFromSnapshot(candidates[candidateIndex]) === activeAccount) {
                    snapshot = candidates[candidateIndex];
                    break;
                }
            }
            if (!snapshot && provider !== "codex") {
                for (var readyIndex = 0; readyIndex < candidates.length; readyIndex++) {
                    if (sampleFrom(candidates[readyIndex])) {
                        snapshot = candidates[readyIndex];
                        break;
                    }
                }
            }
            if (!snapshot && provider !== "codex" && candidates.length > 0)
                snapshot = candidates[0];
            var sample = sampleFrom(snapshot);
            var primary = sample && sample.primary ? sample.primary : null;
            var errorKind = snapshot && snapshot.error && snapshot.error.kind ? String(snapshot.error.kind) : "";
            var errorMessage = snapshot && snapshot.error && snapshot.error.message ? String(snapshot.error.message) : "";
            var explicitEnabled = providerEnabledOverrides[provider];
            // A provider the user explicitly enabled is configured even before its first
            // successful fetch. Keep its setup/error card visible just like CodexBar does;
            // explicitly disabled and merely catalogued providers remain out of the popup.
            var configured = explicitEnabled === true || sample !== null || ["authentication_expired", "permission_denied", "rate_limited"].indexOf(errorKind) !== -1;
            var detected = snapshot !== null && explicitEnabled === undefined;
            var userConfigured = explicitEnabled !== undefined;
            var loading = snapshot !== null && snapshot.state === "loading";
            var localHistoryOnly = provider === "copilot" && sample !== null && sample.cost_usage && errorKind === "missing_credential";
            var credentialOwner = provider === "copilot" ? copilotCredentialOwner(sample) : "";
            var status = loading ? "Loading…" : (localHistoryOnly ? "Local history only" : (provider === "copilot" && errorKind === "permission_denied" ? "Copilot access unavailable" : (sample ? (errorKind === "" ? "Connected" : errorKind.replace(/_/g, " ")) : (errorKind === "authentication_expired" ? "Sign in again" : (errorKind === "missing_credential" || errorKind === "" ? "Not configured" : errorKind.replace(/_/g, " "))))));
            return {
                provider: provider,
                label: labelForProvider(provider),
                percent: sample ? percentFrom(sample) : 0,
                ready: sample !== null,
                loading: loading,
                configured: configured,
                enabled: isProviderEnabled(provider, snapshot !== null),
                detected: detected,
                userConfigured: userConfigured,
                eligibleToEnable: configured || detected || userConfigured,
                errorKind: errorKind,
                errorMessage: errorMessage,
                status: status,
                reset: primary ? (primary.resets_at ? formatResetAt(primary.resets_at) : (primary.reset_description ? String(primary.reset_description) : "")) : "",
                plan: provider === "copilot" && errorKind !== "" ? "" : identityPlanFrom(sample),
                account: sample && sample.identity ? String(sample.identity.email || sample.identity.account_label || "") : "",
                loginMethod: authenticationFrom(sample, provider),
                updated: sample && sample.fetched_at ? String(sample.fetched_at) : "",
                source: localHistoryOnly ? "local history" : sourceFrom(sample, provider),
                health: sample && sample.status ? String(sample.status.health || "") : "",
                refreshing: snapshot && snapshot.refresh ? snapshot.refresh.state === "refreshing" : false,
                stale: snapshot && snapshot.freshness ? snapshot.freshness.state === "stale" : false,
                staleSince: snapshot && snapshot.freshness && snapshot.freshness.state === "stale" ? String(snapshot.freshness.since || "") : "",
                windows: sample ? windowsFrom(sample, provider) : [],
                summary: sample ? summaryFrom(sample) : "",
                optionalSections: sample ? optionalSectionsFrom(sample) : [],
                costStats: sample ? costStatsFrom(sample.cost_usage) : [],
                costChart: sample ? costChartFrom(sample.cost_usage) : null,
                costCaption: sample ? costCaptionFrom(sample.cost_usage, provider) : "",
                detailSections: sample && Array.isArray(sample.detail_sections) ? sample.detail_sections : [],
                configurationHint: provider === "copilot" && errorKind === "permission_denied" ? "GitHub recognizes the account but reports no active Copilot feature access. Check the subscription, assigned seat, or organization policy; repeated login will not restore entitlement." : (provider === "copilot" && credentialOwner === "environment" ? "Using an explicit COPILOT_API_TOKEN environment override. Omarchy AI Bar cannot remove that value; update the user-service environment to sign out." : configurationHintFor(provider)),
                environmentKey: environmentKeyFor(provider),
                endpoint: savedEndpointFor(provider),
                supportsEndpoint: supportsEndpoint(provider),
                canStoreCredential: manualCredentialProviders().indexOf(provider) !== -1,
                canLaunchLogin: loginCommandFor(provider).length > 0,
                credentialOwner: credentialOwner,
                canLogout: provider === "copilot" && copilotAppSessionConfigured && credentialOwner !== "environment"
            };
        });
    }

    function providerIds() {
        var catalog = catalogProviderIds();
        var values = [];
        var configuredOrder = Array.isArray(providerOrder) ? providerOrder : [];
        for (var orderIndex = 0; orderIndex < configuredOrder.length; orderIndex++) {
            var orderedProvider = String(configuredOrder[orderIndex] || "");
            if (catalog.indexOf(orderedProvider) !== -1 && values.indexOf(orderedProvider) === -1)
                values.push(orderedProvider);
        }
        for (var catalogIndex = 0; catalogIndex < catalog.length; catalogIndex++) {
            if (values.indexOf(catalog[catalogIndex]) === -1)
                values.push(catalog[catalogIndex]);
        }
        return values;
    }

    function catalogProviderIds() {
        return ["codex", "openai", "azureopenai", "claude", "clinepass", "cursor", "opencode", "opencodego", "alibaba", "alibabatokenplan", "qwencloud", "factory", "fireworks", "gemini", "antigravity", "copilot", "devin", "zai", "minimax", "manus", "kimi", "kilo", "kiro", "vertexai", "augment", "jetbrains", "moonshot", "amp", "t3chat", "ollama", "synthetic", "openrouter", "elevenlabs", "warp", "windsurf", "zed", "perplexity", "mimo", "doubao", "sakana", "abacus", "mistral", "deepseek", "deepinfra", "codebuff", "crof", "venice", "commandcode", "qoder", "stepfun", "bedrock", "grok", "groq", "llmproxy", "litellm", "deepgram", "poe", "chutes", "neuralwatt", "clawrouter", "longcat", "sub2api", "wayfinder", "zenmux", "aiand", "zoommate", "xai", "notion", "ibmbob"];
    }

    function isProviderEnabled(provider, detected) {
        var value = providerEnabledOverrides[String(provider || "")];
        return value === undefined ? detected === true : value === true;
    }

    function endpointProviders() {
        return ["azureopenai", "kimi", "ollama", "groq", "clawrouter", "openrouter", "wayfinder", "sub2api", "llmproxy", "litellm", "neuralwatt", "codebuff", "chutes", "deepgram"];
    }

    function supportsEndpoint(provider) {
        return endpointProviders().indexOf(String(provider || "")) !== -1;
    }

    function savedEndpointFor(provider) {
        var value = providerEndpointOverrides[String(provider || "")];
        return typeof value === "string" ? value : "";
    }

    function providerEndpointCommand(provider, endpoint, clearEndpoint) {
        return [bridgeExecutable, "config", "set-endpoint", String(provider || "")].concat(clearEndpoint === true ? ["--clear"] : [String(endpoint || "")]);
    }

    function applyProviderSettingsDocument(document) {
        var mapped = {};
        var descriptors = document && Array.isArray(document.providers) ? document.providers : [];
        for (var index = 0; index < descriptors.length; index++) {
            var descriptor = descriptors[index];
            var provider = descriptor && descriptor.provider ? String(descriptor.provider) : "";
            if (providerIds().indexOf(provider) === -1 || Number(descriptor.schema_version || 0) !== 1 || !Array.isArray(descriptor.controls))
                continue;
            mapped[provider] = descriptor;
        }
        providerSettingsDescriptors = mapped;
        providerSettingsDescriptorsLoaded = true;
        loadCredentialSlotStatuses();
    }

    function typedSettingsDescriptor(provider) {
        var descriptor = providerSettingsDescriptors[String(provider || "")];
        return descriptor && Array.isArray(descriptor.controls) ? descriptor : null;
    }

    function typedControlDescriptor(control) {
        return control && control.descriptor ? control.descriptor : null;
    }

    function typedControlItem(control) {
        return typedControlDescriptor(control);
    }

    function typedControl(provider, settingId) {
        var descriptor = typedSettingsDescriptor(provider);
        var controls = descriptor ? descriptor.controls : [];
        for (var index = 0; index < controls.length; index++) {
            var item = typedControlItem(controls[index]);
            if (item && String(item.id || "") === String(settingId || ""))
                return controls[index];
        }
        return null;
    }

    function typedAction(provider, actionId) {
        var descriptor = typedSettingsDescriptor(provider);
        var actions = descriptor && Array.isArray(descriptor.actions) ? descriptor.actions : [];
        for (var index = 0; index < actions.length; index++) {
            if (actions[index] && String(actions[index].id || "") === String(actionId || ""))
                return actions[index];
        }
        return null;
    }

    function typedActionsForControl(provider, control) {
        var item = typedControlItem(control);
        var actionIds = item && Array.isArray(item.actions) ? item.actions : [];
        return actionIds.map(function (actionId) {
            return typedAction(provider, actionId);
        }).filter(function (action) {
            return action !== null;
        });
    }

    function typedStandaloneActions(provider, features) {
        var descriptor = typedSettingsDescriptor(provider);
        var actions = descriptor && Array.isArray(descriptor.actions) ? descriptor.actions : [];
        return actions.filter(function (action) {
            return action && action.standalone === true && evaluateProviderSettingCondition(provider, action.visible_when, features, 0);
        });
    }

    function typedAccountActions(provider) {
        var descriptor = typedSettingsDescriptor(provider);
        var accounts = descriptor ? descriptor.accounts : null;
        if (!accounts)
            return [];
        var identifiers = [accounts.primary_action, accounts.token_file_action];
        var actions = [];
        for (var index = 0; index < identifiers.length; index++) {
            if (!identifiers[index])
                continue;
            var action = typedAction(provider, identifiers[index]);
            if (action && action.standalone !== true && actions.indexOf(action) === -1)
                actions.push(action);
        }
        return actions;
    }

    function hasImplementedTypedActionTarget(provider, target) {
        var descriptor = typedSettingsDescriptor(provider);
        var actions = descriptor && Array.isArray(descriptor.actions) ? descriptor.actions : [];
        return actions.some(function (action) {
            return action && String(action.target || "") === String(target || "") && availabilityImplemented(action.availability);
        });
    }

    function runTypedAction(provider, actionId) {
        var action = typedAction(provider, actionId);
        if (!action || !availabilityImplemented(action.availability))
            return false;
        switch (String(action.target || "")) {
        case "login":
            return launchLogin(provider);
        case "add_managed_account":
            return launchManagedCodexAccount();
        case "open_usage_dashboard":
            return openDashboard(provider);
        case "refresh_provider":
            return refreshProvider(provider);
        case "open_regional_credential_page":
            return openRegionalCredentialPage(provider);
        case "open_token_file":
            return openProviderTokenFile(provider);
        default:
            return false;
        }
    }

    function launchManagedCodexAccount() {
        if (loginLauncher.running || bridgeExecutable === "")
            return false;
        loginLauncher.command = ["omarchy", "launch", "terminal", bridgeExecutable, "codex", "login"];
        loginLauncher.running = true;
        providerConfigResult = "Managed Codex login opened in a terminal";
        return true;
    }

    function managedCodexAccounts() {
        var routes = providerAccountRoutes.codex || [];
        var active = activeProviderAccounts.codex || "ambient";
        var snapshots = effectiveSnapshot && Array.isArray(effectiveSnapshot.snapshots) ? effectiveSnapshot.snapshots : [];
        return routes.map(function (route) {
            var id = String(route.id || "");
            var snapshot = null;
            for (var index = 0; index < snapshots.length; index++) {
                var candidate = snapshots[index];
                var scope = candidate && candidate.scope ? candidate.scope : (candidate && candidate.last_known_good ? candidate.last_known_good.scope : null);
                if (scope && String(scope.provider || "") === "codex" && String(scope.account || "") === id) {
                    snapshot = candidate;
                    break;
                }
            }
            var sample = sampleFrom(snapshot);
            return {
                id: id,
                email: sample && sample.identity ? String(sample.identity.email || sample.identity.account_label || "") : "",
                plan: sample && sample.identity ? String(sample.identity.plan || "") : "",
                active: active === id,
                enabled: route.enabled === true,
                resetLabel: bankedResetsLabel(sample, snapshot),
                state: snapshot ? String(snapshot.state || "") : "missing"
            };
        });
    }

    function ambientCodexAccount() {
        var snapshots = effectiveSnapshot && Array.isArray(effectiveSnapshot.snapshots) ? effectiveSnapshot.snapshots : [];
        for (var index = 0; index < snapshots.length; index++) {
            var candidate = snapshots[index];
            if (providerIdFromSnapshot(candidate) !== "codex" || accountIdFromSnapshot(candidate) !== "ambient")
                continue;
            var sample = sampleFrom(candidate);
            return {
                email: sample && sample.identity ? String(sample.identity.email || sample.identity.account_label || "") : "",
                plan: sample && sample.identity ? String(sample.identity.plan || "") : "",
                resetLabel: bankedResetsLabel(sample, candidate)
            };
        }
        return {
            email: "",
            plan: "",
            resetLabel: "Banked resets unavailable"
        };
    }

    function codexAccountChoices() {
        var ambient = ambientCodexAccount();
        var active = activeProviderAccounts.codex || "ambient";
        var choices = [
            {
                id: "ambient",
                email: ambient.email,
                plan: ambient.plan,
                resetLabel: ambient.resetLabel,
                active: active === "ambient",
                ambient: true
            }
        ];
        return choices.concat(managedCodexAccounts().filter(function (account) {
            return account.enabled;
        }).map(function (account) {
            return {
                id: account.id,
                email: account.email,
                plan: account.plan,
                resetLabel: account.resetLabel,
                active: account.active,
                ambient: false
            };
        }));
    }

    function activateCodexAccount(account) {
        var id = String(account || "");
        if (id === "" || providerConfigBusy || codexAccountWriter.running)
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Selecting Codex account for display…";
        codexAccountWriter.command = [bridgeExecutable, "codex", "activate", id];
        codexAccountWriter.running = true;
        return true;
    }

    function removeCodexAccount(account) {
        var id = String(account || "");
        if (id === "" || id === "ambient" || providerConfigBusy || codexAccountWriter.running)
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Removing Codex account…";
        codexAccountWriter.command = [bridgeExecutable, "codex", "remove", id];
        codexAccountWriter.running = true;
        return true;
    }

    function openRegionalCredentialPage(provider) {
        var providerId = String(provider || "");
        if (providerId !== "zai" || dashboardLauncher.running)
            return false;
        var url = regionalCredentialPageUrl(providerId);
        if (url === "")
            return false;
        dashboardLauncher.command = ["omarchy", "launch", "browser", url];
        dashboardLauncher.running = true;
        providerConfigResult = "Opening regional API keys";
        return true;
    }

    function regionalCredentialPageUrl(provider) {
        var providerId = String(provider || "");
        if (providerId !== "zai")
            return "";
        var regionControl = typedControl(providerId, "zai-api-region");
        var region = regionControl ? String(providerSettingValue(providerId, regionControl)) : "global";
        return region === "bigmodel-cn" ? "https://bigmodel.cn/usercenter/proj-mgmt/apikeys" : "https://z.ai/manage-apikey/apikey";
    }

    function openProviderTokenFile(provider) {
        var command = providerTokenFileCommand(provider, Quickshell.env("HOME"));
        if (command.length === 0 || tokenFileLauncher.running)
            return false;
        tokenFileLauncher.command = command;
        tokenFileLauncher.running = true;
        providerConfigResult = "Opening Grok's provider-owned token file";
        return true;
    }

    function providerTokenFileCommand(provider, homeDirectory) {
        var providerId = String(provider || "");
        var userHome = String(homeDirectory || "");
        if (providerId !== "grok" || userHome.length < 2 || userHome.charAt(0) !== "/" || userHome.length > 4096 || userHome.indexOf("\0") !== -1)
            return [];
        return ["omarchy", "launch", "editor", userHome + "/.grok/auth.json"];
    }

    function availabilityImplemented(availability) {
        return availability && String(availability.state || "") === "implemented";
    }

    function typedControlImplemented(control) {
        var item = typedControlItem(control);
        return item !== null && availabilityImplemented(item.availability);
    }

    function typedPickerOptions(control, implementedOnly) {
        var item = typedControlItem(control);
        var options = item && item.options ? Array.from(item.options) : [];
        return options.filter(function (option) {
            return option && (!implementedOnly || availabilityImplemented(option.availability));
        }).map(function (option) {
            return {
                value: String(option.choice || ""),
                label: String(option.title || option.choice || "")
            };
        });
    }

    function unavailableTypedPickerOptionLabels(control) {
        var item = typedControlItem(control);
        var options = item && item.options ? Array.from(item.options) : [];
        return options.filter(function (option) {
            return option && !availabilityImplemented(option.availability);
        }).map(function (option) {
            return String(option.title || option.choice || "");
        });
    }

    function providerOptionObject(provider) {
        var options = providerOptionsOverrides[String(provider || "")];
        return options && typeof options === "object" ? options : {};
    }

    function explicitProviderSettingValue(provider, settingId) {
        var options = providerOptionObject(provider);
        var extensions = options.provider_options && typeof options.provider_options === "object" ? options.provider_options : {};
        switch (String(settingId || "")) {
        case "codex-usage-source":
        case "claude-usage-source":
        case "grok-usage-source":
            return options.source;
        case "grok-cookie-source":
            return options.cookie_source;
        case "codex-spark-usage-visible":
            return extensions.spark_usage_visible;
        case "codex-external-oauth-sources":
            return extensions.external_oauth_sources;
        case "copilot-budget-extras":
            return options.extras_enabled;
        case "copilot-budget-cookie-source":
            return options.cookie_source;
        case "copilot-enterprise-host":
            return options.enterprise_host;
        case "zai-api-region":
            return options.region;
        default:
            return undefined;
        }
    }

    function providerSettingExplicit(provider, settingId) {
        var value = explicitProviderSettingValue(provider, settingId);
        return value !== undefined && value !== null;
    }

    function defaultProviderSettingValue(provider, control) {
        var item = typedControlItem(control);
        var settingId = item ? String(item.id || "") : "";
        if (settingId === "codex-spark-usage-visible")
            return true;
        if (settingId === "zai-api-region")
            return "global";
        if (String(control && control.kind || "") === "toggle")
            return false;
        if (String(control && control.kind || "") === "plain_option")
            return "";
        if (String(control && control.kind || "") === "picker") {
            var options = typedPickerOptions(control, false);
            return options.length > 0 ? options[0].value : "";
        }
        return "";
    }

    function providerSettingValue(provider, control) {
        var item = typedControlItem(control);
        if (!item)
            return "";
        var explicitValue = explicitProviderSettingValue(provider, item.id);
        return explicitValue === undefined || explicitValue === null ? defaultProviderSettingValue(provider, control) : explicitValue;
    }

    function evaluateProviderSettingCondition(provider, condition, features, depth) {
        var level = Number(depth || 0);
        if (!condition || level > 16)
            return false;
        var kind = String(condition.condition || "");
        if (kind === "always")
            return true;
        if (kind === "all" || kind === "any") {
            var nested = Array.isArray(condition.conditions) ? condition.conditions : [];
            if (kind === "all") {
                for (var allIndex = 0; allIndex < nested.length; allIndex++) {
                    if (!evaluateProviderSettingCondition(provider, nested[allIndex], features, level + 1))
                        return false;
                }
                return true;
            }
            for (var anyIndex = 0; anyIndex < nested.length; anyIndex++) {
                if (evaluateProviderSettingCondition(provider, nested[anyIndex], features, level + 1))
                    return true;
            }
            return false;
        }
        if (kind === "choice" || kind === "toggle") {
            var dependency = typedControl(provider, condition.setting);
            if (!dependency)
                return false;
            var current = providerSettingValue(provider, dependency);
            return kind === "choice" ? String(current) === String(condition.choice || "") : Boolean(current) === (condition.enabled === true);
        }
        if (kind === "feature") {
            var featureValue = features && features[String(condition.feature || "")];
            return Boolean(featureValue) === (condition.enabled === true);
        }
        if (kind === "runtime_fact" && String(condition.fact || "") === "configured-accounts-present")
            return providerAccountPresence[String(provider || "")] === true;
        return false;
    }

    function typedControlsForSection(provider, section, features) {
        var descriptor = typedSettingsDescriptor(provider);
        var controls = descriptor ? descriptor.controls : [];
        return controls.filter(function (control) {
            var item = typedControlItem(control);
            return item && String(item.section || "") === String(section || "") && evaluateProviderSettingCondition(provider, item.visible_when, features, 0);
        });
    }

    function hasTypedSecretControl(provider) {
        var descriptor = typedSettingsDescriptor(provider);
        var controls = descriptor ? descriptor.controls : [];
        return controls.some(function (control) {
            return control && String(control.kind || "") === "secret_slot";
        });
    }

    function implementedCredentialSlot(provider, slot) {
        var descriptor = typedSettingsDescriptor(provider);
        var controls = descriptor ? descriptor.controls : [];
        return controls.some(function (control) {
            var item = typedControlItem(control);
            return control && String(control.kind || "") === "secret_slot" && item && String(item.slot || "") === String(slot || "") && availabilityImplemented(item.availability);
        });
    }

    function credentialSlotKey(provider, slot) {
        return String(provider || "") + "|" + String(slot || "");
    }

    function credentialSlotState(provider, slot) {
        return credentialSlotStates[credentialSlotKey(provider, slot)] || "unknown";
    }

    function setCredentialSlotState(provider, slot, state) {
        var next = {};
        for (var key in credentialSlotStates)
            next[key] = credentialSlotStates[key];
        next[credentialSlotKey(provider, slot)] = String(state || "unknown");
        credentialSlotStates = next;
    }

    function queueCredentialSlotStatus(provider, slot) {
        var providerId = String(provider || "");
        var slotId = String(slot || "");
        var key = credentialSlotKey(providerId, slotId);
        if (!implementedCredentialSlot(providerId, slotId) || key === activeCredentialStatusKey)
            return false;
        for (var index = 0; index < credentialStatusQueue.length; index++) {
            if (credentialStatusQueue[index].key === key)
                return true;
        }
        var queue = credentialStatusQueue.slice(0);
        queue.push({
            provider: providerId,
            slot: slotId,
            key: key
        });
        credentialStatusQueue = queue;
        setCredentialSlotState(providerId, slotId, "checking");
        startNextCredentialSlotStatus();
        return true;
    }

    function startNextCredentialSlotStatus() {
        if (credentialStatusReader.running || credentialStatusQueue.length === 0 || bridgeExecutable === "")
            return;
        var queue = credentialStatusQueue.slice(0);
        var next = queue.shift();
        credentialStatusQueue = queue;
        activeCredentialStatusKey = next.key;
        credentialStatusReader.provider = next.provider;
        credentialStatusReader.slot = next.slot;
        credentialStatusReader.command = [bridgeExecutable, "credential", "status", next.provider, "--slot", next.slot];
        credentialStatusReader.running = true;
    }

    function loadCredentialSlotStatuses() {
        for (var provider in providerSettingsDescriptors) {
            var descriptor = typedSettingsDescriptor(provider);
            var controls = descriptor ? descriptor.controls : [];
            for (var index = 0; index < controls.length; index++) {
                var control = controls[index];
                var item = typedControlItem(control);
                if (control && String(control.kind || "") === "secret_slot" && item && availabilityImplemented(item.availability))
                    queueCredentialSlotStatus(provider, item.slot);
            }
        }
    }

    function providerOptionCommand(provider, settingId, value, clearValue) {
        return [bridgeExecutable, "config", "set-option", String(provider || ""), String(settingId || "")].concat(clearValue === true ? ["--clear"] : [String(value)]);
    }

    function sourceFrom(sample, provider) {
        if (provider === "copilot") {
            var owner = copilotCredentialOwner(sample);
            if (owner === "application")
                return "app oauth";
            if (owner === "environment")
                return "environment oauth";
        }
        var provenance = sample && Array.isArray(sample.provenance) ? sample.provenance : [];
        if (provenance.length > 0 && provenance[0] && provenance[0].strategy)
            return String(provenance[0].strategy).replace(/_/g, " ");
        if (provider === "copilot")
            return "app oauth";
        if (loginCommandFor(provider).length > 0)
            return "native client";
        if (manualCredentialProviders().indexOf(provider) !== -1)
            return "Secret Service";
        if (environmentKeyFor(provider) !== "")
            return "environment";
        return "automatic";
    }

    function copilotCredentialOwner(sample) {
        var provenance = sample && Array.isArray(sample.provenance) ? sample.provenance : [];
        for (var index = 0; index < provenance.length; index++) {
            var entry = provenance[index];
            if (entry && String(entry.source || "") === "credential_owner")
                return String(entry.strategy || "");
        }
        return "";
    }

    function identityPlanFrom(sample) {
        if (!sample || !sample.identity)
            return "";
        if (sample.identity.plan)
            return String(sample.identity.plan);
        var fallback = String(sample.identity.login_method || "");
        var lower = fallback.toLowerCase();
        if (lower.indexOf("oauth") !== -1 || lower.indexOf("token") !== -1 || lower.indexOf("cookie") !== -1 || lower.indexOf("api key") !== -1 || lower === "cli" || lower === "gcloud")
            return "";
        return fallback;
    }

    function authenticationFrom(sample, provider) {
        var method = sample && sample.identity ? String(sample.identity.login_method || "") : "";
        var lower = method.toLowerCase();
        if (lower.indexOf("oauth") !== -1 || lower.indexOf("token") !== -1 || lower.indexOf("cookie") !== -1 || lower.indexOf("api key") !== -1 || lower === "cli" || lower === "gcloud")
            return method;
        return sourceFrom(sample, provider);
    }

    function manualCredentialProviders() {
        return ["abacus", "aiand", "alibaba", "amp", "azureopenai", "chutes", "clawrouter", "clinepass", "codebuff", "commandcode", "crof", "cursor", "deepgram", "deepinfra", "deepseek", "devin", "doubao", "elevenlabs", "factory", "fireworks", "groq", "ibmbob", "kilo", "kimi", "litellm", "llmproxy", "longcat", "manus", "mimo", "minimax", "mistral", "moonshot", "neuralwatt", "notion", "ollama", "openai", "opencode", "opencodego", "openrouter", "perplexity", "poe", "qoder", "qwencloud", "sakana", "stepfun", "sub2api", "synthetic", "t3chat", "venice", "warp", "xai", "zai", "zenmux", "zoommate"];
    }

    function environmentKeyFor(provider) {
        var keys = {
            openai: "OPENAI_API_KEY",
            azureopenai: "AZURE_OPENAI_API_KEY",
            clinepass: "CLINEPASS_API_KEY",
            opencodego: "OPENCODE_API_KEY",
            factory: "FACTORY_API_KEY",
            fireworks: "FIREWORKS_API_KEY",
            zai: "Z_AI_API_KEY",
            moonshot: "MOONSHOT_API_KEY",
            ollama: "OLLAMA_API_KEY",
            synthetic: "SYNTHETIC_API_KEY",
            openrouter: "OPENROUTER_API_KEY",
            elevenlabs: "ELEVENLABS_API_KEY",
            warp: "WARP_API_KEY",
            zed: "ZED_ACCESS_TOKEN",
            deepseek: "DEEPSEEK_API_KEY",
            deepinfra: "DEEPINFRA_API_KEY",
            codebuff: "CODEBUFF_API_KEY",
            crof: "CROF_API_KEY",
            venice: "VENICE_API_KEY",
            groq: "GROQ_API_KEY",
            llmproxy: "LLM_PROXY_API_KEY",
            litellm: "LITELLM_API_KEY",
            deepgram: "DEEPGRAM_API_KEY",
            poe: "POE_API_KEY",
            chutes: "CHUTES_API_KEY",
            neuralwatt: "NEURALWATT_API_KEY",
            clawrouter: "CLAWROUTER_API_KEY",
            sub2api: "SUB2API_API_KEY",
            zenmux: "ZENMUX_MANAGEMENT_API_KEY",
            aiand: "AIAND_API_KEY",
            xai: "XAI_MANAGEMENT_API_KEY",
            ibmbob: "BOBSHELL_API_KEY"
        };
        return keys[provider] || "";
    }

    function loginCommandFor(provider) {
        var commands = {
            codex: ["codex", "login"],
            claude: ["claude"],
            grok: ["grok", "login"],
            copilot: [bridgeExecutable, "copilot", "login"],
            kiro: ["kiro-cli", "login"],
            augment: ["augment", "login"],
            amp: ["amp"],
            gemini: ["gemini"]
        };
        return commands[provider] || [];
    }

    function configurationHintFor(provider) {
        if (provider === "copilot")
            return "Sign in with GitHub for Omarchy AI Bar. Its app-owned OAuth session is separate from Copilot CLI and GitHub CLI credentials.";
        if (manualCredentialProviders().indexOf(provider) !== -1) {
            var environmentKey = environmentKeyFor(provider);
            if (supportsEndpoint(provider) && environmentKey !== "")
                return "Paste " + environmentKey + " securely. You can save a custom provider endpoint below.";
            if (supportsEndpoint(provider))
                return "Paste the provider credential securely. You can save a custom provider endpoint below.";
            if (environmentKey !== "")
                return "Paste " + environmentKey + ". It is stored in Secret Service and explicit service environment values keep precedence.";
            return "Paste the provider session credential. It is stored in Secret Service.";
        }
        var login = loginCommandFor(provider);
        if (login.length > 0)
            return "Open the provider login flow in a terminal, then refresh.";
        var key = environmentKeyFor(provider);
        if (key !== "")
            return "Configure " + key + " for the user service, then restart Omarchy AI Bar.";
        if (provider === "bedrock" || provider === "vertexai" || provider === "doubao")
            return "Configure the provider's standard cloud credentials for the user service.";
        if (provider === "wayfinder")
            return "Start the local Wayfinder gateway or configure WAYFINDER_GATEWAY_URL.";
        return "Install or sign in to the provider's native Linux client, then refresh.";
    }

    function dashboardUrlFor(provider) {
        var urls = {
            codex: "https://chatgpt.com/codex/settings/usage",
            openai: "https://platform.openai.com/usage",
            claude: "https://claude.ai/settings/usage",
            amp: "https://ampcode.com/settings/usage",
            copilot: "https://github.com/settings/copilot",
            grok: "https://grok.com/?_s=usage",
            xai: "https://console.x.ai",
            zai: "https://z.ai/manage-apikey/coding-plan/personal/my-plan",
            gemini: "https://gemini.google.com",
            groq: "https://console.groq.com/dashboard/usage",
            perplexity: "https://www.perplexity.ai/account/usage",
            windsurf: "https://windsurf.com/subscription/usage",
            mistral: "https://admin.mistral.ai/organization/usage",
            vertexai: "https://console.cloud.google.com/vertex-ai",
            fireworks: "https://app.fireworks.ai",
            elevenlabs: "https://elevenlabs.io/app/developers/usage"
        };
        return urls[String(provider || "")] || "";
    }

    function hasDashboard(provider) {
        return dashboardUrlFor(provider) !== "";
    }

    function openDashboard(provider) {
        var url = dashboardUrlFor(provider);
        if (url === "" || dashboardLauncher.running)
            return false;
        dashboardLauncher.command = ["omarchy", "launch", "browser", url];
        dashboardLauncher.running = true;
        providerConfigResult = "Opening " + labelForProvider(provider) + " dashboard";
        return true;
    }

    function openProjectLink(link) {
        var urls = {
            source: "https://github.com/hancengiz/omarchy-ai-bar",
            author: "https://cengizhan.bio",
            codexbar: "https://github.com/steipete/CodexBar"
        };
        var url = urls[String(link || "")] || "";
        if (url === "" || dashboardLauncher.running)
            return false;
        dashboardLauncher.command = ["omarchy", "launch", "browser", url];
        dashboardLauncher.running = true;
        providerConfigResult = "Opening project link";
        return true;
    }

    function windowRow(title, window) {
        if (!window || !window.usage)
            return null;
        var known = window.usage.state === "known" && isFinite(Number(window.usage.used_percent));
        return {
            title: title,
            known: known,
            percent: known ? Math.max(0, Math.min(100, Number(window.usage.used_percent))) : 0,
            reset: window.resets_at ? formatResetAt(window.resets_at) : (window.reset_description ? String(window.reset_description) : ""),
            resetsAt: window.resets_at ? String(window.resets_at) : "",
            durationSeconds: window.duration_seconds !== null && window.duration_seconds !== undefined ? Number(window.duration_seconds) : 0,
            nextRegenPercent: window.next_regen_percent,
            syntheticPlaceholder: window.synthetic_placeholder === true
        };
    }

    function formatResetAt(value) {
        var raw = String(value || "");
        if (raw === "")
            return "";
        var parsed = new Date(raw);
        if (isNaN(parsed.getTime()))
            return raw;
        return Qt.formatDateTime(parsed, "ddd HH:mm");
    }

    function windowTitle(fallback, window, provider) {
        var providerId = String(provider || "");
        if (providerId === "copilot" && fallback === "Primary")
            return "Premium";
        if (providerId === "copilot" && fallback === "Secondary")
            return "Chat";
        var seconds = window && window.duration_seconds !== null ? Number(window.duration_seconds) : 0;
        if (seconds > 0 && seconds <= 21600)
            return "Session";
        if (seconds > 21600 && seconds <= 691200)
            return "Weekly";
        if (seconds > 691200 && seconds <= 2764800)
            return "Monthly";
        if (providerId === "grok") {
            if (fallback === "Primary") {
                if (window && window.resets_at) {
                    var reset = new Date(String(window.resets_at));
                    if (!isNaN(reset.getTime())) {
                        var remainingSeconds = (reset.getTime() - Date.now()) / 1000;
                        if (remainingSeconds > 3600) {
                            var days = Math.round(remainingSeconds / 86400);
                            if (days >= 4 && days <= 12)
                                return "Weekly";
                            if (days >= 20 && days <= 45)
                                return "Monthly";
                        }
                    }
                }
                return "Credits";
            }
            if (fallback === "Secondary")
                return "On-demand";
        }
        return fallback;
    }

    function windowsFrom(sample, provider) {
        var values = [];
        var primary = windowRow(windowTitle("Primary", sample.primary, provider), sample.primary);
        var secondary = windowRow(windowTitle("Secondary", sample.secondary, provider), sample.secondary);
        var tertiary = windowRow(windowTitle("Tertiary", sample.tertiary, provider), sample.tertiary);
        if (primary)
            values.push(primary);
        if (secondary)
            values.push(secondary);
        if (tertiary)
            values.push(tertiary);
        var extras = Array.isArray(sample.extra_windows) ? sample.extra_windows : [];
        for (var index = 0; index < extras.length; index++) {
            var extra = extras[index];
            if (provider === "codex" && extra && String(extra.id || "").indexOf("codex-spark") === 0 && explicitProviderSettingValue("codex", "codex-spark-usage-visible") === false)
                continue;
            var row = extra ? windowRow(String(extra.title || "Quota"), extra.window) : null;
            if (row)
                values.push(row);
        }
        return values;
    }

    function summaryFrom(sample) {
        var values = [];
        if (sample.credits && sample.credits.remaining !== null && sample.credits.remaining !== undefined && (String(sample.credits.remaining) !== "0" || sample.credits.limit !== null || (Array.isArray(sample.credits.events) && sample.credits.events.length > 0)))
            values.push(String(sample.credits.remaining) + " credits");
        if (sample.balance && sample.balance.amount !== undefined)
            values.push(String(sample.balance.amount) + (sample.balance.currency ? " " + String(sample.balance.currency) : ""));
        if (sample.cost && sample.cost.used && sample.cost.used.amount !== undefined)
            values.push(String(sample.cost.used.amount) + (sample.cost.used.currency ? " " + String(sample.cost.used.currency) : "") + " used");
        return values.join(" · ");
    }

    function amountText(amount, unit) {
        if (amount === null || amount === undefined)
            return "Unavailable";
        var value = String(amount);
        var suffix = String(unit || "");
        return value + (suffix !== "" ? " " + suffix : "");
    }

    function usedPercentFromAmounts(used, limit) {
        var usedNumber = Number(used);
        var limitNumber = Number(limit);
        if (!isFinite(usedNumber) || !isFinite(limitNumber) || limitNumber <= 0)
            return -1;
        return Math.max(0, Math.min(100, usedNumber / limitNumber * 100));
    }

    function creditSectionFrom(credits) {
        if (!credits)
            return null;
        var events = Array.isArray(credits.events) ? credits.events : [];
        var limit = credits.limit || null;
        if (String(credits.remaining || "0") === "0" && !limit && events.length === 0)
            return null;
        var rows = [
            {
                label: "Remaining",
                value: amountText(credits.remaining, "credits"),
                sensitivity: "public"
            }
        ];
        if (events.length > 0)
            rows.push({
                label: "Recent activity",
                value: events.length + (events.length === 1 ? " credit event" : " credit events"),
                sensitivity: "personal"
            });
        var metric = null;
        if (limit) {
            var percent = limit.remaining_percent !== null && limit.remaining_percent !== undefined ? 100 - Number(limit.remaining_percent) : usedPercentFromAmounts(limit.used, limit.limit);
            metric = {
                title: String(limit.title || "Credit limit"),
                known: isFinite(percent) && percent >= 0,
                percent: isFinite(percent) ? Math.max(0, Math.min(100, percent)) : 0,
                reset: formatResetAt(limit.resets_at),
                resetsAt: limit.resets_at ? String(limit.resets_at) : "",
                durationSeconds: 0,
                nextRegenPercent: null,
                syntheticPlaceholder: false
            };
            if (limit.limit !== null && limit.limit !== undefined)
                rows.push({
                    label: "Limit",
                    value: amountText(limit.limit, "credits"),
                    sensitivity: "public"
                });
        }
        return {
            id: "credits",
            title: "Credits",
            metric: metric,
            rows: rows,
            caption: "",
            captionSensitivity: "public"
        };
    }

    function bankedResetsFrom(inventory) {
        if (!inventory || typeof inventory.reported_available_count !== "number")
            return null;
        var count = inventory.reported_available_count;
        if (!isFinite(count) || count < 0 || Math.floor(count) !== count)
            return null;
        var updatedAt = Date.parse(inventory.updated_at || "");
        var credits = Array.isArray(inventory.credits) ? inventory.credits : [];
        var nextExpiry = null;
        for (var index = 0; index < credits.length; index++) {
            var credit = credits[index];
            if (String(credit.status || "") !== "available" || !credit.expires_at)
                continue;
            var expiry = Date.parse(credit.expires_at);
            // The reported count already excludes credits expired when fetched.
            if (expiry <= resetInventoryNow && expiry > updatedAt)
                count = Math.max(0, count - 1);
            if (expiry > resetInventoryNow && (!nextExpiry || expiry < Date.parse(nextExpiry)))
                nextExpiry = credit.expires_at;
        }
        return {
            available: count,
            expiresAt: nextExpiry
        };
    }

    function bankedResetsLabel(sample, snapshot) {
        var inventory = bankedResetsFrom(sample ? sample.reset_credits : null);
        if (!inventory)
            return "Banked resets unavailable";
        var label = inventory.available + (inventory.available === 1 ? " banked reset" : " banked resets");
        if (snapshot && (snapshot.error || (snapshot.freshness && snapshot.freshness.state === "stale")))
            label += " (last known)";
        return label;
    }

    function resetCreditsSectionFrom(resetCredits, showUnavailable) {
        var inventory = bankedResetsFrom(resetCredits);
        if (!inventory && !showUnavailable)
            return null;
        var rows = [
            {
                label: "Available",
                value: inventory ? inventory.available + (inventory.available === 1 ? " reset" : " resets") : "Unavailable",
                sensitivity: "public"
            }
        ];
        if (inventory && inventory.available > 0 && inventory.expiresAt) {
            rows.push({
                label: "Next expiry",
                value: formatResetAt(inventory.expiresAt),
                sensitivity: "public"
            });
        }
        return {
            id: "reset-credits",
            title: "Banked resets",
            metric: null,
            rows: rows,
            caption: "",
            captionSensitivity: "public"
        };
    }

    function budgetSectionFrom(sample) {
        var cost = sample ? sample.cost : null;
        var balance = sample ? sample.balance : null;
        if (!cost && !balance)
            return null;
        var currency = cost && cost.used ? String(cost.used.currency || "") : (balance ? String(balance.currency || "") : "");
        var rows = [];
        var metric = null;
        if (cost && cost.used) {
            rows.push({
                label: cost.period ? String(cost.period) + " spend" : "Spend",
                value: amountText(cost.used.amount, currency),
                sensitivity: "public"
            });
            var percent = usedPercentFromAmounts(cost.used.amount, cost.limit);
            if (percent >= 0) {
                metric = {
                    title: cost.period ? String(cost.period) + " budget" : "Budget",
                    known: true,
                    percent: percent,
                    reset: formatResetAt(cost.resets_at),
                    resetsAt: cost.resets_at ? String(cost.resets_at) : "",
                    durationSeconds: 0,
                    nextRegenPercent: null,
                    syntheticPlaceholder: false
                };
                rows.push({
                    label: "Limit",
                    value: amountText(cost.limit, currency),
                    sensitivity: "public"
                });
            }
            if (cost.personal_used !== null && cost.personal_used !== undefined)
                rows.push({
                    label: "Personal spend",
                    value: amountText(cost.personal_used, currency),
                    sensitivity: "personal"
                });
            if (cost.next_regen_amount !== null && cost.next_regen_amount !== undefined)
                rows.push({
                    label: "Next regen",
                    value: amountText(cost.next_regen_amount, currency),
                    sensitivity: "public"
                });
        }
        var balanceAmount = cost && cost.balance !== null && cost.balance !== undefined ? cost.balance : (balance ? balance.amount : null);
        if (balanceAmount !== null && balanceAmount !== undefined)
            rows.push({
                label: "Balance",
                value: amountText(balanceAmount, currency),
                sensitivity: "public"
            });
        return rows.length === 0 ? null : {
            id: "budget",
            title: cost ? "Budget & Balance" : "Balance",
            metric: metric,
            rows: rows,
            caption: cost && cost.provenance ? String(cost.provenance).replace(/_/g, " ") : "",
            captionSensitivity: "public"
        };
    }

    function optionalSectionsFrom(sample) {
        var sections = [creditSectionFrom(sample.credits), resetCreditsSectionFrom(sample.reset_credits, sample.scope && sample.scope.provider === "codex"), budgetSectionFrom(sample)];
        return sections.filter(function (section) {
            return section !== null;
        });
    }

    function compactQuantity(value) {
        var numeric = Number(value || 0);
        if (!isFinite(numeric))
            return String(value || "0");
        var scales = [
            {
                value: 1000000000,
                suffix: "B"
            },
            {
                value: 1000000,
                suffix: "M"
            },
            {
                value: 1000,
                suffix: "K"
            }
        ];
        for (var index = 0; index < scales.length; index++) {
            if (Math.abs(numeric) >= scales[index].value) {
                var scaled = numeric / scales[index].value;
                return scaled.toFixed(scaled >= 100 ? 0 : (scaled >= 10 ? 1 : 2)).replace(/\.0+$/, "") + scales[index].suffix;
            }
        }
        return Math.round(numeric).toString();
    }

    function currencyPrefix(costUsage) {
        return costUsage && costUsage.unit && costUsage.unit.kind === "currency" && String(costUsage.unit.code || "") === "USD" ? "$" : "";
    }

    function formatAmount(costUsage, value) {
        if (value === null || value === undefined)
            return "Unavailable";
        var numeric = Number(value);
        var unit = costUsage && costUsage.unit ? String(costUsage.unit.code || costUsage.unit.unit || "") : "";
        var rendered = isFinite(numeric) ? numeric.toLocaleString(Qt.locale(), "f", numeric >= 100 ? 0 : 2) : String(value);
        return currencyPrefix(costUsage) + rendered + (currencyPrefix(costUsage) === "" && unit !== "" ? " " + unit : "");
    }

    function costStatsFrom(costUsage) {
        if (!costUsage || !costUsage.history || !costUsage.session)
            return [];
        var values = [];
        var todayAmount = costUsage.session.amount;
        var historyAmount = costUsage.history.amount;
        if (todayAmount !== null && todayAmount !== undefined)
            values.push({
                label: "Today",
                value: formatAmount(costUsage, todayAmount)
            });
        if (historyAmount !== null && historyAmount !== undefined)
            values.push({
                label: "Last " + String(costUsage.history_days || 30) + " days cost",
                value: formatAmount(costUsage, historyAmount)
            });
        if (costUsage.session.total_tokens !== null && costUsage.session.total_tokens !== undefined)
            values.push({
                label: "Today tokens",
                value: compactQuantity(costUsage.session.total_tokens)
            });
        if (costUsage.history.total_tokens !== null && costUsage.history.total_tokens !== undefined)
            values.push({
                label: "Last " + String(costUsage.history_days || 30) + " days tokens",
                value: compactQuantity(costUsage.history.total_tokens)
            });
        return values;
    }

    function costChartFrom(costUsage) {
        if (!costUsage || !Array.isArray(costUsage.daily) || costUsage.daily.length === 0)
            return null;
        var useCost = costUsage.daily.some(function (bucket) {
            return bucket && bucket.metrics && bucket.metrics.amount !== null && bucket.metrics.amount !== undefined;
        });
        return {
            kind: "bar",
            title: useCost ? "Daily estimated cost" : "Daily tokens",
            unit: useCost ? (currencyPrefix(costUsage) || String(costUsage.unit.unit || "")) : "tokens",
            points: costUsage.daily.map(function (bucket) {
                var raw = useCost ? bucket.metrics.amount : bucket.metrics.total_tokens;
                return {
                    label: String(bucket.day || "").slice(5),
                    value: Number(raw || 0)
                };
            })
        };
    }

    function costCaptionFrom(costUsage, provider) {
        if (!costUsage)
            return "";
        var models = {};
        var daily = Array.isArray(costUsage.daily) ? costUsage.daily : [];
        for (var dayIndex = 0; dayIndex < daily.length; dayIndex++) {
            var rows = daily[dayIndex] && Array.isArray(daily[dayIndex].models) ? daily[dayIndex].models : [];
            for (var modelIndex = 0; modelIndex < rows.length; modelIndex++) {
                var name = String(rows[modelIndex].name || "unknown");
                models[name] = Number(models[name] || 0) + Number(rows[modelIndex].metrics.total_tokens || 0);
            }
            if (rows.length === 0 && daily[dayIndex] && Array.isArray(daily[dayIndex].models_used)) {
                for (var usedIndex = 0; usedIndex < daily[dayIndex].models_used.length; usedIndex++) {
                    var usedName = String(daily[dayIndex].models_used[usedIndex] || "unknown");
                    models[usedName] = Number(models[usedName] || 0) + 1;
                }
            }
        }
        var names = Object.keys(models).sort(function (left, right) {
            return models[right] - models[left];
        });
        var prefix = names.length > 0 ? "Top model: " + names[0] + " · " : "";
        var source = provider === "claude" ? "Claude" : (provider === "codex" ? "Codex" : labelForProvider(provider));
        if (String(costUsage.provenance || "") === "list_price_estimate")
            return prefix + "Estimated from local " + source + " logs";
        if (provider === "grok")
            return prefix + "Local Grok session history";
        if (provider === "copilot")
            return prefix + "Local Copilot CLI history";
        return prefix + "Local usage history";
    }

    function percentFrom(sample) {
        if (!sample)
            return 0;
        var windows = windowsFrom(sample);
        var maximum = 0;
        for (var index = 0; index < windows.length; index++) {
            if (windows[index].known)
                maximum = Math.max(maximum, Number(windows[index].percent || 0));
        }
        return Math.max(0, Math.min(100, maximum));
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
                loadProviderConfig();
                loadCopilotSessionStatus();
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

    function refreshProvider(provider) {
        var value = String(provider || "");
        if (providerIds().indexOf(value) === -1)
            return false;
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
        if (!writeLine(Protocol.refreshProviderLine(requestId, value))) {
            connectionError = "backend_unavailable";
            if (!bridgeProcess.running)
                scheduleReconnect("backend_unavailable");
            return false;
        }
        return true;
    }

    function loadProviderConfig() {
        if (providerConfigReader.running) {
            providerConfigReloadPending = true;
            return false;
        }
        if (bridgeExecutable === "")
            return false;
        providerConfigReloadPending = false;
        providerConfigReader.command = [bridgeExecutable, "config", "show", "--format", "json"];
        providerConfigReader.running = true;
        return true;
    }

    function loadProviderSettingsDescriptors() {
        if (providerSettingsDescriptorReader.running || bridgeExecutable === "")
            return false;
        providerSettingsDescriptorReader.command = [bridgeExecutable, "config", "describe", "--format", "json"];
        providerSettingsDescriptorReader.running = true;
        return true;
    }

    function loadCopilotSessionStatus() {
        if (copilotStatusReader.running || bridgeExecutable === "")
            return false;
        copilotStatusReader.command = [bridgeExecutable, "copilot", "status"];
        copilotStatusReader.running = true;
        return true;
    }

    function applyProviderConfigDocument(document) {
        var overrides = {};
        var order = [];
        var endpoints = {};
        var options = {};
        var accounts = {};
        var accountRoutes = {};
        var activeAccounts = {};
        var configuredOrder = document && document.config && Array.isArray(document.config.provider_order) ? document.config.provider_order : [];
        var catalog = catalogProviderIds();
        for (var orderIndex = 0; orderIndex < configuredOrder.length; orderIndex++) {
            var orderedProvider = String(configuredOrder[orderIndex] || "");
            if (catalog.indexOf(orderedProvider) !== -1 && order.indexOf(orderedProvider) === -1)
                order.push(orderedProvider);
        }
        var providers = document && document.config && Array.isArray(document.config.providers) ? document.config.providers : [];
        for (var index = 0; index < providers.length; index++) {
            var route = providers[index];
            if (!route || String(route.instance_id || "") !== "default" || !route.id)
                continue;
            var provider = String(route.id);
            overrides[provider] = route.enabled === true;
            endpoints[provider] = typeof route.endpoint === "string" ? route.endpoint : "";
            options[provider] = route.options && typeof route.options === "object" ? route.options : {};
            accounts[provider] = Array.isArray(route.accounts) && route.accounts.length > 0;
            accountRoutes[provider] = Array.isArray(route.accounts) ? route.accounts : [];
            var extensions = route.options && route.options.provider_options && typeof route.options.provider_options === "object" ? route.options.provider_options : {};
            activeAccounts[provider] = typeof extensions.active_account === "string" ? extensions.active_account : "ambient";
        }
        providerEnabledOverrides = overrides;
        providerOrder = order;
        providerEndpointOverrides = endpoints;
        providerOptionsOverrides = options;
        providerAccountPresence = accounts;
        providerAccountRoutes = accountRoutes;
        activeProviderAccounts = activeAccounts;
        providerConfigLoaded = true;
    }

    function providerReorderCommand(providers) {
        if (!Array.isArray(providers) || providers.length === 0 || providers.length > catalogProviderIds().length)
            return [];
        var catalog = catalogProviderIds();
        var values = [];
        for (var index = 0; index < providers.length; index++) {
            var provider = String(providers[index] || "");
            if (catalog.indexOf(provider) === -1 || values.indexOf(provider) !== -1)
                return [];
            values.push(provider);
        }
        return [bridgeExecutable, "config", "reorder"].concat(values);
    }

    function setProviderOrder(providers) {
        var command = providerReorderCommand(providers);
        if (providerConfigBusy || providerOrderWriter.running || bridgeExecutable === "" || command.length === 0)
            return false;
        var next = providers.slice(0);
        for (var index = 0; index < providerOrder.length; index++) {
            if (next.indexOf(providerOrder[index]) === -1)
                next.push(providerOrder[index]);
        }
        providerOrder = next;
        providerConfigBusy = true;
        providerConfigResult = "Saving provider order…";
        providerOrderWriter.command = command;
        providerOrderWriter.running = true;
        return true;
    }

    function setProviderEnabled(provider, enabled) {
        if (providerConfigBusy || providerConfigWriter.running || provider === "")
            return false;
        var next = {};
        for (var key in providerEnabledOverrides)
            next[key] = providerEnabledOverrides[key];
        next[provider] = enabled === true;
        providerEnabledOverrides = next;
        providerConfigBusy = true;
        providerConfigResult = "Saving…";
        providerConfigWriter.provider = provider;
        providerConfigWriter.desiredEnabled = enabled === true;
        providerConfigWriter.command = [bridgeExecutable, "config", enabled ? "enable" : "disable", provider];
        providerConfigWriter.running = true;
        return true;
    }

    function setProviderEndpoint(provider, endpoint) {
        var providerId = String(provider || "");
        var value = String(endpoint || "").trim();
        if (providerConfigBusy || endpointConfigWriter.running || !supportsEndpoint(providerId) || value.length === 0 || value.length > 2048 || bridgeExecutable === "")
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Saving endpoint…";
        endpointConfigWriter.provider = providerId;
        endpointConfigWriter.endpoint = value;
        endpointConfigWriter.clearEndpoint = false;
        endpointConfigWriter.keepEnabled = providerRows.some(function (row) {
            return row && row.provider === providerId && row.enabled === true;
        });
        endpointConfigWriter.command = providerEndpointCommand(providerId, value, false);
        endpointConfigWriter.running = true;
        return true;
    }

    function clearProviderEndpoint(provider) {
        var providerId = String(provider || "");
        if (providerConfigBusy || endpointConfigWriter.running || !supportsEndpoint(providerId) || bridgeExecutable === "")
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Clearing endpoint…";
        endpointConfigWriter.provider = providerId;
        endpointConfigWriter.endpoint = "";
        endpointConfigWriter.clearEndpoint = true;
        endpointConfigWriter.keepEnabled = false;
        endpointConfigWriter.command = providerEndpointCommand(providerId, "", true);
        endpointConfigWriter.running = true;
        return true;
    }

    function setProviderOption(provider, settingId, value) {
        var providerId = String(provider || "");
        var settingKey = String(settingId || "");
        var control = typedControl(providerId, settingKey);
        var item = typedControlItem(control);
        if (providerConfigBusy || providerOptionWriter.running || bridgeExecutable === "" || !control || !item || !typedControlImplemented(control) || String(control.kind || "") === "secret_slot")
            return false;
        var optionValue = value;
        if (String(control.kind || "") === "picker") {
            optionValue = String(value || "");
            var supported = typedPickerOptions(control, true).some(function (option) {
                return option.value === optionValue;
            });
            if (!supported)
                return false;
        } else if (String(control.kind || "") === "toggle") {
            if (value !== true && value !== false)
                return false;
            optionValue = value ? "true" : "false";
        } else {
            optionValue = String(value || "").trim();
            if (optionValue.length === 0 || optionValue.length > 2048)
                return false;
        }
        providerConfigBusy = true;
        providerConfigResult = "Saving " + String(item.title || "provider setting") + "…";
        providerOptionWriter.provider = providerId;
        providerOptionWriter.settingId = settingKey;
        providerOptionWriter.clearValue = false;
        providerOptionWriter.keepEnabled = providerRows.some(function (row) {
            return row && row.provider === providerId && row.enabled === true;
        });
        providerOptionWriter.command = providerOptionCommand(providerId, settingKey, optionValue, false);
        providerOptionWriter.running = true;
        return true;
    }

    function clearProviderOption(provider, settingId) {
        var providerId = String(provider || "");
        var settingKey = String(settingId || "");
        var control = typedControl(providerId, settingKey);
        if (providerConfigBusy || providerOptionWriter.running || bridgeExecutable === "" || !control || !typedControlImplemented(control) || String(control.kind || "") === "secret_slot")
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Restoring provider default…";
        providerOptionWriter.provider = providerId;
        providerOptionWriter.settingId = settingKey;
        providerOptionWriter.clearValue = true;
        providerOptionWriter.keepEnabled = providerRows.some(function (row) {
            return row && row.provider === providerId && row.enabled === true;
        });
        providerOptionWriter.command = providerOptionCommand(providerId, settingKey, "", true);
        providerOptionWriter.running = true;
        return true;
    }

    function storeManualCredential(provider, secret) {
        if (providerConfigBusy || credentialWriter.running || manualCredentialProviders().indexOf(provider) === -1)
            return false;
        var value = String(secret || "");
        if (value.length === 0 || value.length > 16384)
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Saving credential…";
        pendingCredential = value;
        credentialWriter.provider = provider;
        credentialWriter.slot = "";
        credentialWriter.command = [bridgeExecutable, "credential", "set", provider];
        // Give every one-shot invocation a fresh stdin pipe, then close it
        // immediately after the bounded newline-delimited credential record.
        credentialWriter.stdinEnabled = true;
        credentialWriter.running = true;
        return true;
    }

    function storeCredentialSlot(provider, slot, secret) {
        var providerId = String(provider || "");
        var slotId = String(slot || "");
        var value = String(secret || "");
        if (providerConfigBusy || credentialWriter.running || bridgeExecutable === "" || !implementedCredentialSlot(providerId, slotId) || value.length === 0 || value.length > 16384)
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Saving credential securely…";
        pendingCredential = value;
        setCredentialSlotState(providerId, slotId, "saving");
        credentialWriter.provider = providerId;
        credentialWriter.slot = slotId;
        credentialWriter.command = [bridgeExecutable, "credential", "set", providerId, "--slot", slotId];
        credentialWriter.stdinEnabled = true;
        credentialWriter.running = true;
        return true;
    }

    function deleteCredentialSlot(provider, slot) {
        var providerId = String(provider || "");
        var slotId = String(slot || "");
        if (providerConfigBusy || credentialDeleteWriter.running || bridgeExecutable === "" || !implementedCredentialSlot(providerId, slotId))
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Deleting credential…";
        setCredentialSlotState(providerId, slotId, "deleting");
        credentialDeleteWriter.provider = providerId;
        credentialDeleteWriter.slot = slotId;
        credentialDeleteWriter.command = [bridgeExecutable, "credential", "delete", providerId, "--slot", slotId];
        credentialDeleteWriter.running = true;
        return true;
    }

    function launchLogin(provider) {
        var login = loginCommandFor(provider);
        if (login.length === 0 || loginLauncher.running)
            return false;
        loginLauncher.command = ["omarchy", "launch", "terminal"].concat(login);
        loginLauncher.running = true;
        providerConfigResult = "Login opened in a terminal";
        return true;
    }

    function logoutProvider(provider) {
        if (provider !== "copilot" || logoutLauncher.running || providerConfigBusy)
            return false;
        providerConfigBusy = true;
        providerConfigResult = "Signing out…";
        logoutLauncher.command = [bridgeExecutable, "copilot", "logout"];
        logoutLauncher.running = true;
        return true;
    }

    function restartDaemonAfterConfiguration() {
        if (daemonRestart.running)
            return;
        daemonRestart.command = ["systemctl", "--user", "restart", "omarchy-ai-bar.service"];
        daemonRestart.running = true;
    }

    Process {
        id: providerConfigReader
        running: false
        stdout: StdioCollector {
            id: providerConfigOutput
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (root.providerConfigReloadPending)
                Qt.callLater(root.loadProviderConfig);
            if (exitCode !== 0) {
                root.providerConfigLoaded = true;
                root.providerConfigResult = "Could not read provider settings";
                return;
            }
            try {
                root.applyProviderConfigDocument(JSON.parse(providerConfigOutput.text || "{}"));
            } catch (error) {
                root.providerConfigLoaded = true;
                root.providerConfigResult = "Provider settings are invalid";
            }
        }
    }

    Process {
        id: providerSettingsDescriptorReader
        running: false
        stdout: StdioCollector {
            id: providerSettingsDescriptorOutput
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (exitCode !== 0) {
                root.providerSettingsDescriptors = {};
                root.providerSettingsDescriptorsLoaded = true;
                return;
            }
            try {
                root.applyProviderSettingsDocument(JSON.parse(providerSettingsDescriptorOutput.text || "{}"));
            } catch (error) {
                root.providerSettingsDescriptors = {};
                root.providerSettingsDescriptorsLoaded = true;
            }
        }
    }

    Process {
        id: credentialStatusReader
        property string provider: ""
        property string slot: ""
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (root.credentialSlotState(provider, slot) === "checking")
                root.setCredentialSlotState(provider, slot, exitCode === 0 ? "configured" : (exitCode === 69 ? "not_configured" : "unknown"));
            root.activeCredentialStatusKey = "";
            root.startNextCredentialSlotStatus();
        }
    }

    Process {
        id: copilotStatusReader
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            root.copilotAppSessionConfigured = exitCode === 0;
            root.copilotSessionStatusLoaded = true;
        }
    }

    Process {
        id: providerConfigWriter
        property string provider: ""
        property bool desiredEnabled: true
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (exitCode === 0) {
                root.providerConfigResult = (desiredEnabled ? "Enabled " : "Disabled ") + root.labelForProvider(provider);
                root.restartDaemonAfterConfiguration();
            } else {
                root.providerConfigBusy = false;
                root.providerConfigResult = "Could not save provider setting";
                root.loadProviderConfig();
            }
        }
    }

    Process {
        id: providerOrderWriter
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            root.providerConfigBusy = false;
            root.providerConfigResult = exitCode === 0 ? "Provider order saved" : "Could not save provider order";
            root.loadProviderConfig();
        }
    }

    Process {
        id: endpointConfigWriter
        property string provider: ""
        property string endpoint: ""
        property bool clearEndpoint: false
        property bool keepEnabled: false
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (exitCode === 0) {
                var next = {};
                for (var key in root.providerEndpointOverrides)
                    next[key] = root.providerEndpointOverrides[key];
                next[provider] = clearEndpoint ? "" : endpoint;
                root.providerEndpointOverrides = next;
                root.providerConfigResult = clearEndpoint ? "Endpoint cleared" : "Endpoint saved";
                // `config set-endpoint` creates an otherwise absent route in a
                // disabled state. Preserve a provider that was already active
                // through local detection by materializing its enabled route
                // before the daemon restart.
                if (keepEnabled && root.providerEnabledOverrides[provider] !== true) {
                    var enabled = {};
                    for (var providerKey in root.providerEnabledOverrides)
                        enabled[providerKey] = root.providerEnabledOverrides[providerKey];
                    enabled[provider] = true;
                    root.providerEnabledOverrides = enabled;
                    providerConfigWriter.provider = provider;
                    providerConfigWriter.desiredEnabled = true;
                    providerConfigWriter.command = [root.bridgeExecutable, "config", "enable", provider];
                    providerConfigWriter.running = true;
                } else {
                    root.restartDaemonAfterConfiguration();
                }
            } else {
                root.providerConfigBusy = false;
                root.providerConfigResult = exitCode === 2 ? "Endpoint rejected; check the URL and provider policy" : "Could not save endpoint";
                root.loadProviderConfig();
            }
        }
    }

    Process {
        id: providerOptionWriter
        property string provider: ""
        property string settingId: ""
        property bool clearValue: false
        property bool keepEnabled: false
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (exitCode === 0) {
                root.providerConfigResult = clearValue ? "Provider default restored" : "Provider setting saved";
                if (keepEnabled && root.providerEnabledOverrides[provider] !== true) {
                    var enabled = {};
                    for (var key in root.providerEnabledOverrides)
                        enabled[key] = root.providerEnabledOverrides[key];
                    enabled[provider] = true;
                    root.providerEnabledOverrides = enabled;
                    providerConfigWriter.provider = provider;
                    providerConfigWriter.desiredEnabled = true;
                    providerConfigWriter.command = [root.bridgeExecutable, "config", "enable", provider];
                    providerConfigWriter.running = true;
                } else {
                    root.restartDaemonAfterConfiguration();
                }
            } else {
                root.providerConfigBusy = false;
                root.providerConfigResult = exitCode === 2 ? "Provider setting was rejected" : "Could not save provider setting";
                root.loadProviderConfig();
            }
        }
    }

    Process {
        id: credentialWriter
        property string provider: ""
        property string slot: ""
        running: false
        stdinEnabled: true
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onStarted: {
            write(root.pendingCredential + "\n");
            root.pendingCredential = "";
            stdinEnabled = false;
        }
        onExited: function (exitCode) {
            root.pendingCredential = "";
            if (exitCode === 0) {
                if (slot !== "")
                    root.setCredentialSlotState(provider, slot, "configured");
                root.providerConfigResult = "Credential saved securely";
                if (root.providerEnabledOverrides[provider] !== true) {
                    var next = {};
                    for (var key in root.providerEnabledOverrides)
                        next[key] = root.providerEnabledOverrides[key];
                    next[provider] = true;
                    root.providerEnabledOverrides = next;
                    providerConfigWriter.provider = provider;
                    providerConfigWriter.desiredEnabled = true;
                    providerConfigWriter.command = [root.bridgeExecutable, "config", "enable", provider];
                    providerConfigWriter.running = true;
                } else {
                    root.restartDaemonAfterConfiguration();
                }
            } else {
                if (slot !== "")
                    root.setCredentialSlotState(provider, slot, "unknown");
                root.providerConfigBusy = false;
                root.providerConfigResult = "Could not save credential";
            }
        }
    }

    Process {
        id: credentialDeleteWriter
        property string provider: ""
        property string slot: ""
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            if (exitCode === 0) {
                root.setCredentialSlotState(provider, slot, "not_configured");
                root.providerConfigResult = "Credential deleted";
                root.restartDaemonAfterConfiguration();
            } else {
                root.setCredentialSlotState(provider, slot, "unknown");
                root.providerConfigBusy = false;
                root.providerConfigResult = "Could not delete credential";
            }
        }
    }

    Process {
        id: dashboardLauncher
        running: false
        onExited: function (exitCode) {
            if (exitCode !== 0)
                root.providerConfigResult = "Could not open provider dashboard";
        }
    }

    Process {
        id: tokenFileLauncher
        running: false
        onExited: function (exitCode) {
            if (exitCode !== 0)
                root.providerConfigResult = "Could not open the provider-owned token file";
        }
    }

    Process {
        id: daemonRestart
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            root.providerConfigBusy = false;
            root.providerConfigResult = exitCode === 0 ? "Settings applied" : "Saved; restart the service to apply";
            root.loadProviderConfig();
            if (exitCode === 0)
                root.scheduleReconnect("configuration_changed");
        }
    }

    Process {
        id: loginLauncher
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
    }

    Process {
        id: codexAccountWriter
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            root.providerConfigBusy = false;
            root.providerConfigResult = exitCode === 0 ? "Codex accounts updated" : "Could not update Codex accounts";
            root.loadProviderConfig();
            if (exitCode === 0)
                root.scheduleReconnect("codex_accounts_changed");
        }
    }

    Process {
        id: logoutLauncher
        running: false
        stdout: StdioCollector {
            waitForEnd: true
        }
        stderr: StdioCollector {
            waitForEnd: true
        }
        onExited: function (exitCode) {
            root.providerConfigBusy = false;
            root.providerConfigResult = exitCode === 0 ? "Removed Omarchy AI Bar's Copilot session" : "Could not sign out of Copilot";
            root.loadCopilotSessionStatus();
            root.loadProviderConfig();
            if (exitCode === 0)
                root.scheduleReconnect("copilot_logout");
        }
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

    Timer {
        interval: 60000
        running: true
        repeat: true
        onTriggered: root.resetInventoryNow = Date.now()
    }

    Component.onCompleted: {
        loadProviderConfig();
        loadProviderSettingsDescriptors();
        loadCopilotSessionStatus();
        startConnection();
    }
    Component.onDestruction: {
        pendingCredential = "";
        credentialStatusQueue = [];
        connectionWanted = false;
        reconnectTimer.stop();
        handshakeTimer.stop();
        forceStopTimer.stop();
        panelRetryTimer.stop();
        if (bridgeProcess.running)
            bridgeProcess.running = false;
    }
}
