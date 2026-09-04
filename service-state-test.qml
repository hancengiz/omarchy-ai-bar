import QtQuick
import Quickshell
import "qml/omarchy-plugin" as Plugin
import "qml/omarchy-plugin/Protocol.js" as Protocol

ShellRoot {
    id: root

    property bool finished: false

    function require(condition, message) {
        if (!condition)
            throw new Error(message);
    }

    function equal(actual, expected, message) {
        if (actual !== expected)
            throw new Error(message + ": expected " + String(expected) + ", received " + String(actual));
    }

    function helloLine(streamId) {
        return JSON.stringify({
            type: "hello",
            protocol: {
                major: 1,
                minor: 0
            },
            stream_id: streamId,
            capabilities: ["display_snapshots", "runtime_actions", "action_progress"]
        });
    }

    function runTests() {
        require(!service.connectionWanted, "disabled service started a connection");
        require(!service.transportConnected, "disabled service exposed a live transport");
        equal(service.effectiveSnapshot.snapshots.length, 0, "disconnected service fabricated a preview snapshot");
        equal(service.configuredProviderRows.length, 0, "disconnected service fabricated a configured provider");
        equal(service.connectionStatus, "Offline", "disconnected service exposed a preview status");
        var endpointProviders = ["azureopenai", "kimi", "ollama", "groq", "clawrouter", "openrouter", "wayfinder", "sub2api", "llmproxy", "litellm", "neuralwatt", "codebuff", "chutes", "deepgram"];
        equal(JSON.stringify(service.endpointProviders()), JSON.stringify(endpointProviders), "endpoint provider registry drifted");
        for (var endpointProviderIndex = 0; endpointProviderIndex < endpointProviders.length; endpointProviderIndex++)
            require(service.supportsEndpoint(endpointProviders[endpointProviderIndex]), "supported endpoint provider was rejected");
        require(!service.supportsEndpoint("zai"), "provider with multiple endpoint roles exposed an ambiguous endpoint field");
        service.applyProviderConfigDocument({
            config: {
                provider_order: ["ollama", "litellm"],
                providers: [
                    {
                        id: "litellm",
                        instance_id: "default",
                        enabled: false,
                        endpoint: "https://llm.example.test"
                    },
                    {
                        id: "litellm",
                        instance_id: "work",
                        enabled: true,
                        endpoint: "https://ignored.example.test"
                    },
                    {
                        id: "ollama",
                        instance_id: "default",
                        enabled: true,
                        options: {
                            source: "auto",
                            region: "global",
                            provider_options: {
                                external_oauth_sources: false
                            }
                        },
                        accounts: [
                            {
                                id: "ambient",
                                enabled: true
                            }
                        ]
                    }
                ]
            }
        });
        equal(service.savedEndpointFor("litellm"), "https://llm.example.test", "default route endpoint was not parsed");
        equal(service.savedEndpointFor("ollama"), "", "missing route endpoint was not normalized");
        require(service.providerEnabledOverrides.litellm === false, "non-default route replaced the default enabled setting");
        equal(JSON.stringify(service.providerIds().slice(0, 2)), JSON.stringify(["ollama", "litellm"]), "configured provider order was ignored");
        var reorderCommand = service.providerReorderCommand(["zai", "codex", "claude"]);
        equal(reorderCommand.slice(1).join(" "), "config reorder zai codex claude", "provider reorder command changed its argument boundaries");
        equal(service.providerReorderCommand(["zai", "zai"]).length, 0, "duplicate provider reorder input was accepted");
        equal(service.providerOptionsOverrides.ollama.source, "auto", "provider options were not retained for settings rendering");
        require(service.providerAccountPresence.ollama === true, "provider account presence was not retained");
        require(service.configuredProviderRows.some(function (row) {
            return row.provider === "ollama";
        }), "explicitly enabled provider disappeared before its first successful sample");
        require(!service.configuredProviderRows.some(function (row) {
            return row.provider === "litellm";
        }), "explicitly disabled provider leaked into the usage popup");
        var loadingRow = service.rowsFrom({
            snapshots: [
                {
                    state: "loading",
                    scope: {
                        provider: "ollama"
                    }
                }
            ]
        }).filter(function (row) {
            return row.provider === "ollama";
        })[0];
        require(loadingRow.loading, "initial provider refresh lost its loading presentation");
        equal(loadingRow.status, "Loading…", "initial provider refresh was mislabeled as unconfigured");
        var litellmRow = service.providerRows.filter(function (row) {
            return row.provider === "litellm";
        })[0];
        require(litellmRow && litellmRow.supportsEndpoint, "provider row omitted endpoint capability");
        equal(litellmRow.endpoint, "https://llm.example.test", "provider row omitted its saved endpoint");
        var literalEndpoint = "https://llm.example.test/path;touch-not-a-shell";
        var endpointCommand = service.providerEndpointCommand("litellm", literalEndpoint, false);
        equal(endpointCommand.length, 5, "endpoint command split an endpoint argument");
        equal(endpointCommand[4], literalEndpoint, "endpoint command changed the literal endpoint argument");
        var clearCommand = service.providerEndpointCommand("litellm", "ignored", true);
        equal(clearCommand.length, 5, "clear endpoint command shape changed");
        equal(clearCommand[4], "--clear", "clear endpoint command omitted its flag");

        service.applyProviderSettingsDocument({
            schema_version: 1,
            providers: [
                {
                    schema_version: 1,
                    provider: "zai",
                    controls: [
                        {
                            kind: "picker",
                            descriptor: {
                                id: "zai-api-region",
                                title: "API region",
                                subtitle: "Choose the regional API.",
                                section: "connection",
                                visible_when: {
                                    condition: "always"
                                },
                                enabled_when: {
                                    condition: "always"
                                },
                                availability: {
                                    state: "implemented"
                                },
                                options: [
                                    {
                                        choice: "global",
                                        title: "Global",
                                        availability: {
                                            state: "implemented"
                                        }
                                    },
                                    {
                                        choice: "bigmodel-cn",
                                        title: "BigModel CN",
                                        availability: {
                                            state: "implemented"
                                        }
                                    }
                                ],
                                actions: []
                            }
                        },
                        {
                            kind: "secret_slot",
                            descriptor: {
                                id: "zai-api-key",
                                title: "API key",
                                subtitle: "Stored securely.",
                                section: "credentials",
                                visible_when: {
                                    condition: "always"
                                },
                                enabled_when: {
                                    condition: "always"
                                },
                                availability: {
                                    state: "implemented"
                                },
                                slot: "zai-api-key",
                                placeholder: "Paste API key",
                                actions: []
                            }
                        },
                        {
                            kind: "toggle",
                            descriptor: {
                                id: "codex-openai-web-extras",
                                title: "Unavailable fixture",
                                subtitle: "Must not become interactive.",
                                section: "options",
                                visible_when: {
                                    condition: "always"
                                },
                                enabled_when: {
                                    condition: "feature",
                                    feature: "optional-credits-and-extra-usage",
                                    enabled: true
                                },
                                availability: {
                                    state: "unavailable",
                                    gap: "openai-web-extras"
                                },
                                actions: []
                            }
                        }
                    ],
                    actions: []
                }
            ]
        });
        require(service.providerSettingsDescriptorsLoaded, "typed settings document did not become ready");
        require(service.typedSettingsDescriptor("zai") !== null, "typed provider descriptor was not indexed");
        require(service.typedSettingsDescriptor("openai") === null, "missing typed provider fabricated a descriptor");
        equal(service.typedControlsForSection("zai", "connection", {}).length, 1, "typed connection section was not filtered");
        require(service.implementedCredentialSlot("zai", "zai-api-key"), "implemented credential slot was rejected");
        require(!service.implementedCredentialSlot("zai", "unknown-slot"), "unknown credential slot was accepted");
        var regionControl = service.typedControl("zai", "zai-api-region");
        equal(service.providerSettingValue("zai", regionControl), "global", "typed picker default drifted");
        require(!service.providerSettingExplicit("zai", "zai-api-region"), "missing region was reported as explicit");
        var optionCommand = service.providerOptionCommand("zai", "zai-api-region", "bigmodel-cn", false);
        equal(optionCommand.length, 6, "provider option command split a value argument");
        equal(optionCommand[5], "bigmodel-cn", "provider option command changed a literal value");
        var clearOptionCommand = service.providerOptionCommand("zai", "zai-api-region", "ignored", true);
        equal(clearOptionCommand[5], "--clear", "provider option clear command omitted its flag");
        service.setCredentialSlotState("zai", "zai-api-key", "configured");
        equal(service.credentialSlotState("zai", "zai-api-key"), "configured", "credential status cache did not retain public state");
        equal(service.regionalCredentialPageUrl("zai"), "https://z.ai/manage-apikey/apikey", "global z.ai credential URL drifted");
        service.applyProviderConfigDocument({
            config: {
                providers: [
                    {
                        id: "zai",
                        instance_id: "default",
                        enabled: false,
                        options: {
                            region: "bigmodel-cn"
                        }
                    },
                    {
                        id: "grok",
                        instance_id: "default",
                        enabled: true,
                        options: {
                            source: "web",
                            cookie_source: "off"
                        }
                    }
                ]
            }
        });
        equal(service.regionalCredentialPageUrl("zai"), "https://bigmodel.cn/usercenter/proj-mgmt/apikeys", "BigModel CN credential URL drifted");
        equal(service.explicitProviderSettingValue("grok", "grok-usage-source"), "web", "Grok source was not restored from provider config");
        equal(service.explicitProviderSettingValue("grok", "grok-cookie-source"), "off", "Grok cookie source was not restored from provider config");
        equal(service.windowTitle("Primary", {
            duration_seconds: null,
            resets_at: new Date(Date.now() + 5 * 86400000).toISOString()
        }, "grok"), "Weekly", "Grok timestamp-only weekly window lost its CodexBar label");
        equal(service.windowTitle("Primary", {
            duration_seconds: null,
            resets_at: new Date(Date.now() + 30 * 86400000).toISOString()
        }, "grok"), "Monthly", "Grok timestamp-only monthly window lost its CodexBar label");
        equal(service.windowTitle("Primary", {
            duration_seconds: null,
            resets_at: null
        }, "grok"), "Credits", "Grok fallback window lost its CodexBar label");
        equal(service.windowTitle("Primary", {
            duration_seconds: 2592000,
            resets_at: null
        }, "copilot"), "Premium", "Copilot primary window lost its CodexBar label");
        equal(service.windowTitle("Secondary", {
            duration_seconds: null,
            resets_at: null
        }, "copilot"), "Chat", "Copilot secondary window lost its CodexBar label");
        var zaiResetAt = "2026-09-05T09:30:00Z";
        var zaiTimedWindow = service.windowRow("Session", {
            usage: {
                state: "known",
                used_percent: 42
            },
            duration_seconds: 18000,
            resets_at: zaiResetAt,
            reset_description: "5-hour",
            next_regen_percent: null,
            synthetic_placeholder: false
        });
        equal(zaiTimedWindow.reset, service.formatResetAt(zaiResetAt), "z.ai concrete reset time was hidden by its cadence description");
        equal(zaiTimedWindow.resetsAt, zaiResetAt, "z.ai concrete reset timestamp was not preserved for pace calculations");
        var zaiPeriodicWindow = service.windowRow("Session", {
            usage: {
                state: "known",
                used_percent: 42
            },
            duration_seconds: 18000,
            resets_at: null,
            reset_description: "5-hour",
            next_regen_percent: null,
            synthetic_placeholder: false
        });
        equal(zaiPeriodicWindow.reset, "5-hour", "z.ai cadence fallback disappeared without a concrete reset time");
        var glanceRows = service.rowsFrom({
            snapshots: [
                {
                    state: "ready",
                    last_known_good: {
                        scope: {
                            provider: "codex"
                        },
                        identity: {
                            email: "user@example.test",
                            plan: "Plus"
                        },
                        fetched_at: "2026-08-31T10:00:00Z",
                        primary: {
                            usage: {
                                state: "known",
                                used_percent: 42
                            },
                            resets_at: zaiResetAt,
                            reset_description: "5-hour",
                            duration_seconds: 18000
                        },
                        credits: {
                            remaining: "25",
                            events: []
                        },
                        cost_usage: {
                            unit: {
                                kind: "currency",
                                code: "USD"
                            },
                            history_days: 30,
                            session: {
                                amount: "1.50",
                                total_tokens: "1200"
                            },
                            history: {
                                amount: "8.25",
                                total_tokens: "9000"
                            },
                            daily: [
                                {
                                    day: "2026-08-31",
                                    metrics: {
                                        amount: "1.50",
                                        total_tokens: "1200"
                                    },
                                    models: []
                                }
                            ]
                        }
                    },
                    freshness: {
                        state: "stale",
                        since: "2026-08-31T10:05:00Z"
                    },
                    refresh: {
                        state: "idle"
                    },
                    error: {
                        kind: "rate_limited",
                        message: "Slow down"
                    }
                }
            ]
        });
        var glanceRow = glanceRows.filter(function (row) {
            return row.provider === "codex";
        })[0];
        equal(glanceRow.account, "user@example.test", "glance card lost account identity");
        equal(glanceRow.plan, "Plus", "glance card lost plan identity");
        require(glanceRow.ready && glanceRow.stale, "last-known usage was not retained under a stale error");
        equal(glanceRow.errorKind, "rate_limited", "stale error overlay classification was lost");
        equal(glanceRow.reset, service.formatResetAt(zaiResetAt), "glance card concrete reset time was hidden by its cadence description");
        equal(glanceRow.windows.length, 1, "glance card lost its quota bars");
        equal(glanceRow.windows[0].title, "Session", "glance card lost its quota window label");
        equal(glanceRow.optionalSections[0].title, "Credits", "glance card lost its credits section");
        equal(glanceRow.costStats.length, 4, "glance card lost its cost and token KPIs");
        equal(glanceRow.costChart.points.length, 1, "glance card lost its daily cost chart");
        var tokenFileCommand = service.providerTokenFileCommand("grok", "/home/test;literal");
        equal(tokenFileCommand.length, 4, "Grok token-file command split the provider path");
        equal(tokenFileCommand[3], "/home/test;literal/.grok/auth.json", "Grok token-file command changed the literal path");
        equal(service.providerTokenFileCommand("claude", "/home/test").length, 0, "non-Grok provider received a token-file action");
        service.connectionWanted = true;
        service.transportConnected = true;
        service.scheduleReconnect("test_disconnect");
        require(!service.connectionWanted, "disconnect retained write intent");
        require(!service.transportConnected, "disconnect retained live status");
        require(!service.writeLine("{}\n"), "disconnected service accepted a write");

        require(service.reportPanelOpened(), "open intent was not retained");
        var openRequest = service.panelStateRequestId;
        require(openRequest > 0, "open intent has no request ID");
        equal(Protocol.requestProgressState(service.protocolState, openRequest), "issued", "open request was not tracked");
        require(service.reportPanelOpened(), "duplicate open intent was rejected");
        equal(service.panelStateRequestId, openRequest, "duplicate open minted a request ID");

        require(service.reportPanelClosed(), "offline close intent was not retained");
        var closeRequest = service.panelStateRequestId;
        require(closeRequest > openRequest, "close did not supersede open");
        service.connectionWanted = true;
        service.transportConnected = true;
        service.handleProtocolLine(helloLine("00000000000000000000000000000001"));
        equal(service.protocolState.phase, "ready", "hello did not ready the service");
        equal(service.panelStateRequestId, closeRequest, "hello replaced replay request ID");
        service.handleProtocolLine(JSON.stringify({
            type: "action_progress",
            request_id: closeRequest,
            state: "completed"
        }));
        require(Protocol.requestIsCompleted(service.protocolState, closeRequest), "completed close was not retained");

        require(service.reportPanelOpened(), "open intent before failure was not retained");
        var failedRequest = service.panelStateRequestId;
        require(failedRequest > closeRequest, "failed-action setup did not mint a request ID");
        service.handleProtocolLine(JSON.stringify({
            type: "action_progress",
            request_id: failedRequest,
            state: "failed"
        }));
        equal(service.panelStateRequestId, 0, "failed panel action was retained as converged");
        equal(service.panelRetryCount, 1, "failed panel action did not consume one bounded retry");
        require(service.panelRetryScheduled, "failed panel action did not schedule backoff");
        service.runPanelRetry();
        var retriedRequest = service.panelStateRequestId;
        require(retriedRequest > failedRequest, "failed panel action reused its terminal request ID");
        equal(Protocol.requestProgressState(service.protocolState, retriedRequest), "issued", "replacement panel request was not tracked");
        service.handleProtocolLine(JSON.stringify({
            type: "action_progress",
            request_id: retriedRequest,
            state: "completed"
        }));
        equal(service.panelRetryCount, 0, "completed retry did not reset its retry budget");
        require(!service.panelRetryScheduled, "completed retry retained a backoff timer");

        service.protocolState = Protocol.reconnectingState(service.protocolState);
        service.handleProtocolLine(helloLine("00000000000000000000000000000002"));
        equal(Protocol.requestProgressState(service.protocolState, retriedRequest), "issued", "new backend epoch did not rearm intent");
        equal(service.panelStateRequestId, retriedRequest, "new backend epoch changed replay ID");
        service.panelRetryCount = service.maxPanelRetries;
        service.handleProtocolLine(JSON.stringify({
            type: "action_progress",
            request_id: retriedRequest,
            state: "failed"
        }));
        equal(service.panelStateRequestId, retriedRequest, "exhausted retry budget discarded terminal evidence");
        equal(service.panelActionError, "panel_state_failed", "exhausted retry budget was not surfaced");
        require(!service.panelRetryScheduled, "exhausted retry budget scheduled an unbounded retry");

        var previousSession = service.sessionId;
        service.nextRequestId = Protocol.MAX_EXACT_INTEGER;
        require(service.reportPanelClosed(), "rotated close intent was not retained");
        require(service.sessionId !== previousSession, "request exhaustion did not rotate session");
        equal(service.panelStateRequestId, 0, "rotated session assigned a request before its new handshake");
        service.connectionWanted = true;
        service.transportConnected = true;
        service.protocolState = Protocol.reconnectingState(service.protocolState);
        service.handleProtocolLine(helloLine("00000000000000000000000000000002"));
        equal(service.panelStateRequestId, 1, "rotated session did not restart request IDs");
        require(!service.panelDesiredOpen, "rotated session lost the latest close intent");

        var saturatedHello = Protocol.reduceLine(Protocol.initialState(), helloLine("00000000000000000000000000000003"));
        require(saturatedHello.accepted, "saturation setup hello failed");
        var saturatedState = saturatedHello.state;
        for (var requestId = 1; requestId <= Protocol.MAX_TRACKED_REQUESTS; requestId++)
            saturatedState = Protocol.registerRequest(saturatedState, requestId);
        saturationService.protocolState = saturatedState;
        saturationService.nextRequestId = Protocol.MAX_TRACKED_REQUESTS + 1;
        require(saturationService.reportPanelOpened(), "saturated service did not retain open UI state");
        equal(saturationService.panelStateRequestId, 0, "saturated service fabricated a tracked open request");
        require(saturationService.reportPanelClosed(), "saturated service did not retain the subsequent close UI state");
        require(!saturationService.panelDesiredOpen, "saturated service retained stale open UI state");
        equal(saturationService.panelStateRequestId, 0, "saturated service fabricated a tracked close request");
        saturationService.handleProtocolLine(JSON.stringify({
            type: "action_progress",
            request_id: 1,
            state: "completed"
        }));
        require(saturationService.panelStateRequestId > Protocol.MAX_TRACKED_REQUESTS, "freed action slot did not admit pending panel intent");
        equal(Protocol.requestProgressState(saturationService.protocolState, saturationService.panelStateRequestId), "issued", "capacity recovery did not track pending close intent");

        var navigationCalls = [];
        var navigationOwner = {
            open: function () {
                navigationCalls.push("usage");
            },
            openProviderSettings: function (provider) {
                navigationCalls.push("provider:" + String(provider || ""));
            },
            openProviderCatalog: function () {
                navigationCalls.push("catalog");
            },
            openAppSettings: function (pane) {
                navigationCalls.push("app:" + String(pane || ""));
            }
        };
        require(service.claimPanel(navigationOwner), "navigation test owner could not claim panel");
        require(service.openFromIpc(), "ordinary IPC open was rejected");
        require(service.openSettingsFromIpc("codex"), "provider settings IPC open was rejected");
        require(service.openProviderCatalogFromIpc(), "provider catalog IPC open was rejected");
        require(service.openAppSettingsFromIpc("display"), "app settings IPC open was rejected");
        equal(JSON.stringify(navigationCalls), JSON.stringify(["usage", "provider:codex", "catalog", "app:display"]), "IPC navigation destinations were conflated");
        service.releasePanel(navigationOwner);

        var closeCount = 0;
        var first = {
            closeForServiceSwitch: function () {
                closeCount += 1;
            }
        };
        var second = {
            closeForServiceSwitch: function () {}
        };
        require(service.claimPanel(first), "first monitor could not claim panel");
        require(service.claimPanel(first), "idempotent claim failed");
        equal(closeCount, 0, "idempotent claim closed its owner");
        require(service.claimPanel(second), "second monitor could not claim panel");
        equal(closeCount, 1, "ownership transfer did not close first monitor");
        require(service.activePanelOwner === second, "ownership transfer chose wrong monitor");
    }

    function finish(success, message) {
        if (finished)
            return;
        finished = true;
        startupDeadline.stop();
        startupPoll.stop();
        forcedStopCheck.stop();
        if (success)
            console.log("OAB_SERVICE_STATE_TEST_PASS");
        else
            console.error("OAB_SERVICE_STATE_TEST_FAIL: " + message);
        Qt.quit();
    }

    Plugin.Service {
        id: service
        bridgeEnabled: false
    }

    Plugin.Service {
        id: terminationService
        bridgeEnabled: false
    }

    Plugin.Service {
        id: saturationService
        bridgeEnabled: false
    }

    Timer {
        interval: 0
        running: true
        repeat: false
        onTriggered: {
            try {
                root.runTests();
                terminationService.bridgeEnabled = true;
                root.require(terminationService.startConnection(), "termination test could not start bridge");
                startupDeadline.restart();
                startupPoll.start();
            } catch (error) {
                root.finish(false, String(error));
            }
        }
    }

    Timer {
        id: startupPoll
        interval: 10
        repeat: true
        onTriggered: {
            if (!terminationService.transportConnected)
                return;
            stop();
            startupDeadline.stop();
            terminationService.scheduleReconnect("forced_stop_test");
            terminationService.bridgeEnabled = false;
            if (terminationService.transportConnected) {
                root.finish(false, "scheduled reconnect retained live status");
                return;
            }
            forcedStopCheck.restart();
        }
    }

    Timer {
        id: startupDeadline
        interval: 2000
        repeat: false
        onTriggered: root.finish(false, "test bridge did not start")
    }

    Timer {
        id: forcedStopCheck
        interval: 1250
        repeat: false
        onTriggered: {
            if (terminationService.bridgeRunning)
                root.finish(false, "SIGKILL fallback did not stop bridge");
            else
                root.finish(true, "");
        }
    }
}
