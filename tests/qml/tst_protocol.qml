import QtQuick
import QtTest
import "../../qml/omarchy-plugin/Protocol.js" as Protocol

TestCase {
    name: "ProtocolReducer"

    readonly property string streamA: "00000000000000000000000000000001"
    readonly property string streamB: "00000000000000000000000000000002"

    function scope(account) {
        return {
            provider: "codex",
            instance: "personal",
            account: account
        };
    }

    function helloLine(major, capabilities, streamId) {
        return JSON.stringify({
            type: "hello",
            protocol: {
                major: major,
                minor: 0
            },
            stream_id: streamId || streamA,
            capabilities: capabilities || ["display_snapshots"]
        });
    }

    function loadingSnapshot(account) {
        return {
            state: "loading",
            scope: scope(account)
        };
    }

    function readySnapshot(duration) {
        var sampleScope = scope("ready-account");
        return {
            state: "ready",
            last_known_good: {
                scope: sampleScope,
                identity: {
                    scope: sampleScope,
                    provider_account_id: null,
                    email: null,
                    organization: null,
                    account_label: "Test account",
                    plan: null,
                    login_method: null
                },
                fetched_at: "2026-08-29T00:00:00Z",
                primary: {
                    usage: {
                        state: "known",
                        used_percent: 42
                    },
                    duration_seconds: duration,
                    resets_at: "2026-08-29T05:00:00Z",
                    reset_description: "in five hours",
                    next_regen_percent: null,
                    synthetic_placeholder: false
                },
                secondary: null,
                tertiary: null,
                extra_windows: [],
                credits: null,
                balance: null,
                cost: null,
                subscription_renews_at: null,
                subscription_expires_at: null,
                reset_credits: null,
                detail_sections: [],
                extensions: [],
                chart_points: [],
                provenance: [],
                confidence: "exact",
                status: {}
            },
            freshness: {
                state: "fresh"
            },
            refresh: {
                state: "idle"
            },
            error: null
        };
    }

    function snapshotObject(account) {
        return {
            schema_version: 1,
            generated_at: "2026-08-29T00:00:00Z",
            snapshots: [loadingSnapshot(account)]
        };
    }

    function snapshotLine(sequence, account) {
        return JSON.stringify({
            type: "snapshot",
            sequence: sequence,
            snapshot: snapshotObject(account)
        });
    }

    function readyState(capabilities, streamId) {
        var result = Protocol.reduceLine(Protocol.initialState(), helloLine(1, capabilities || ["display_snapshots"], streamId || streamA));
        verify(result.accepted);
        return result.state;
    }

    function snapshotMessage(sequence, providerSnapshot) {
        return {
            type: "snapshot",
            sequence: sequence,
            snapshot: {
                schema_version: 1,
                generated_at: "2026-08-29T00:00:00Z",
                snapshots: [providerSnapshot]
            }
        };
    }

    function test_helloNegotiatesCompatibleMajorAndStream() {
        var result = Protocol.reduceLine(Protocol.initialState(), helloLine(1, ["display_snapshots", "runtime_actions"]));

        verify(result.accepted);
        compare(result.state.phase, "ready");
        verify(result.state.compatible);
        compare(result.state.protocol.major, 1);
        compare(result.state.streamId, streamA);
        compare(result.state.capabilities.length, 2);
    }

    function test_unknownForwardCapabilitiesAndRustGrammar() {
        var result = Protocol.reduceLine(Protocol.initialState(), helloLine(1, ["display_snapshots", "1future_widget"]));

        verify(result.accepted);
        compare(result.state.capabilities.length, 1);
        compare(result.state.capabilities[0], "display_snapshots");
        verify(!Protocol.validCapabilities(["future__widget"]));
        verify(!Protocol.validCapabilities(["future_widget_"]));
        verify(Protocol.validCapabilities(["1future_widget"]));
    }

    function test_snapshotReducerReacksEqualAndRejectsOlder() {
        var state = readyState();
        var first = Protocol.reduceLine(state, snapshotLine(7, "current"));
        verify(first.accepted);
        compare(first.ackSequence, 7);
        compare(first.state.lastSequence, 7);
        compare(first.state.snapshot.snapshots[0].scope.account, "current");

        var equal = Protocol.reduceLine(first.state, snapshotLine(7, "duplicate"));
        verify(!equal.accepted);
        verify(equal.stale);
        compare(equal.ackSequence, 7);
        verify(equal.state === first.state);
        compare(equal.state.snapshot.snapshots[0].scope.account, "current");

        var older = Protocol.reduceLine(first.state, snapshotLine(6, "old"));
        verify(!older.accepted);
        verify(older.stale);
        compare(older.ackSequence, 0);
        compare(older.state.lastSequence, 7);

        var newer = Protocol.reduceLine(first.state, snapshotLine(8, "new"));
        verify(newer.accepted);
        compare(newer.state.lastSequence, 8);
        compare(newer.state.snapshot.snapshots[0].scope.account, "new");
    }

    function test_reconnectPreservesSequenceUntilBackendStreamChanges() {
        var first = Protocol.reduceLine(readyState(), snapshotLine(7, "retained"));
        var reconnecting = Protocol.reconnectingState(first.state);
        compare(reconnecting.phase, "awaiting_hello");
        compare(reconnecting.lastSequence, 7);
        compare(reconnecting.snapshot.snapshots[0].scope.account, "retained");

        var sameStream = Protocol.reduceLine(reconnecting, helloLine(1, ["display_snapshots"], streamA));
        verify(sameStream.accepted);
        compare(sameStream.state.lastSequence, 7);
        verify(Protocol.reduceLine(sameStream.state, snapshotLine(6, "old")).stale);

        var restarted = Protocol.reduceLine(Protocol.reconnectingState(sameStream.state), helloLine(1, ["display_snapshots"], streamB));
        verify(restarted.accepted);
        compare(restarted.state.streamId, streamB);
        compare(restarted.state.lastSequence, 0);
        compare(restarted.state.snapshot, null);
        verify(Protocol.reduceLine(restarted.state, snapshotLine(1, "new-daemon")).accepted);
    }

    function test_unsupportedMajorAndServerCompatibilityAreVisible() {
        var unsupported = Protocol.reduceLine(Protocol.initialState(), helloLine(2));
        verify(unsupported.accepted);
        compare(unsupported.state.phase, "incompatible");
        compare(unsupported.state.compatibilityFailure, "unsupported_protocol_major");

        var reported = Protocol.reduceLine(Protocol.initialState(), JSON.stringify({
            type: "compatibility_error",
            code: "hello_required",
            supported: {
                major: 1,
                minor: 0
            }
        }));
        verify(reported.accepted);
        compare(reported.state.compatibilityFailure, "hello_required");
    }

    function test_reducerFailsClosedBeforeHelloAndForUnknownMessages() {
        var beforeHello = Protocol.reduceLine(Protocol.initialState(), snapshotLine(1, "too-soon"));
        verify(!beforeHello.accepted);
        verify(beforeHello.fatal);
        compare(beforeHello.error, "hello_required");

        var unknown = Protocol.reduceLine(readyState(), "{\"type\":\"execute\"}");
        verify(!unknown.accepted);
        compare(unknown.error, "unknown_message_type");
    }

    function test_featureMessagesRequireNegotiatedCapabilities() {
        var progress = JSON.stringify({
            type: "action_progress",
            request_id: 1,
            state: "running"
        });
        compare(Protocol.reduceLine(readyState(), progress).error, "capability_not_negotiated");

        var tracked = Protocol.registerRequest(readyState(["display_snapshots", "action_progress"]), 1);
        var accepted = Protocol.reduceLine(tracked, progress);
        verify(accepted.accepted);
        compare(accepted.state.lastActionProgress.request_id, 1);

        compare(Protocol.reduceLine(readyState(["display_snapshots", "action_progress"]), progress).error, "unsolicited_action_progress");
        var completed = Protocol.reduceLine(accepted.state, JSON.stringify({
            type: "action_progress",
            request_id: 1,
            state: "completed"
        }));
        verify(completed.accepted);
        verify(Protocol.requestIsCompleted(completed.state, 1));
        compare(Protocol.reduceLine(completed.state, progress).error, "invalid_action_progress_transition");

        var failedState = Protocol.registerRequest(accepted.state, 2);
        var failed = Protocol.reduceMessage(failedState, {
            type: "action_progress",
            request_id: 2,
            state: "failed"
        });
        verify(failed.accepted);
        verify(Protocol.requestIsTerminal(failed.state, 2));
        verify(!Protocol.requestIsCompleted(failed.state, 2));
    }

    function test_frameSchemaAndCollectionBoundsAreEnforced() {
        compare(Protocol.reduceLine(Protocol.initialState(), "{not-json}").error, "malformed_json");
        compare(Protocol.reduceLine(Protocol.initialState(), "{}\n{}").error, "invalid_frame");

        var oversized = "";
        for (var i = 0; i < Protocol.MAX_MESSAGE_BYTES; i++)
            oversized += "x";
        compare(Protocol.reduceLine(Protocol.initialState(), oversized).error, "invalid_frame");

        var tooManySnapshots = [];
        for (var j = 0; j <= Protocol.MAX_SNAPSHOTS; j++)
            tooManySnapshots.push(loadingSnapshot("account-" + j));
        var invalid = Protocol.reduceMessage(readyState(), {
            type: "snapshot",
            sequence: 1,
            snapshot: {
                schema_version: 1,
                generated_at: "2026-08-29T00:00:00Z",
                snapshots: tooManySnapshots
            }
        });
        compare(invalid.error, "invalid_snapshot");
    }

    function test_snapshotTreeRejectsHostileNumbersDepthAndVariants() {
        var numericU64 = snapshotMessage(1, readySnapshot(60));
        compare(Protocol.reduceMessage(readyState(), numericU64).error, "invalid_snapshot");

        var leadingZero = snapshotMessage(1, readySnapshot("060"));
        compare(Protocol.reduceMessage(readyState(), leadingZero).error, "invalid_snapshot");

        var overflow = snapshotMessage(1, readySnapshot("18446744073709551616"));
        compare(Protocol.reduceMessage(readyState(), overflow).error, "invalid_snapshot");

        var unsafeInteger = readySnapshot("60");
        unsafeInteger.last_known_good.primary.usage.used_percent = 9007199254740992;
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, unsafeInteger)).error, "invalid_snapshot");

        var deep = readySnapshot("60");
        var cursor = deep.last_known_good.identity;
        for (var depth = 0; depth <= Protocol.MAX_SNAPSHOT_DEPTH; depth++) {
            cursor.child = {};
            cursor = cursor.child;
        }
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, deep)).error, "invalid_snapshot");

        var tooWide = readySnapshot("60");
        tooWide.last_known_good.identity.items = [];
        for (var item = 0; item <= Protocol.MAX_SNAPSHOT_ARRAY_ITEMS; item++)
            tooWide.last_known_good.identity.items.push(item);
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, tooWide)).error, "invalid_snapshot");

        var wrongVariant = loadingSnapshot("wrong");
        wrongVariant.extra = true;
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, wrongVariant)).error, "invalid_snapshot");

        var unknownSampleKey = readySnapshot("60");
        unknownSampleKey.last_known_good.unreviewed = true;
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, unknownSampleKey)).error, "invalid_snapshot");

        var missingIdentitySchema = readySnapshot("60");
        missingIdentitySchema.last_known_good.identity = {};
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, missingIdentitySchema)).error, "invalid_snapshot");

        var numericCredits = readySnapshot("60");
        numericCredits.last_known_good.credits = 7;
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, numericCredits)).error, "invalid_snapshot");

        var impossiblePlaceholder = readySnapshot("60");
        impossiblePlaceholder.last_known_good.primary.synthetic_placeholder = true;
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, impossiblePlaceholder)).error, "invalid_snapshot");
    }

    function test_nonfiniteExponentAndNoncanonicalOuterIntegerFail() {
        var canonical = JSON.stringify(snapshotMessage(1, readySnapshot("60")));
        var nonfinite = canonical.replace("\"used_percent\":42", "\"used_percent\":1e309");
        compare(Protocol.reduceLine(readyState(), nonfinite).error, "malformed_json");

        var exponentId = canonical.replace("\"sequence\":1", "\"sequence\":1e0");
        compare(Protocol.reduceLine(readyState(), exponentId).error, "noncanonical_integer");
    }

    function test_jsonPrimitivesFailClosedWithoutThrowing() {
        var inputs = ["null", "true", "7", "\"message\"", "[]"];
        for (var i = 0; i < inputs.length; i++) {
            var result = Protocol.reduceLine(Protocol.initialState(), inputs[i]);
            verify(!result.accepted);
            compare(result.error, "invalid_message");
        }
    }

    function test_classifiedErrorsAndPositiveDurationsAreStrict() {
        var retryable = {
            kind: "network",
            code: "provider.network",
            message: "The provider could not be reached.",
            retry: "automatic",
            auth_implication: "none",
            retry_after: "60"
        };
        verify(Protocol.validClassifiedError(retryable));

        var invalidValues = [0, "0", "060", "not-a-duration", "18446744073709551616"];
        for (var i = 0; i < invalidValues.length; i++) {
            var invalid = Object.assign({}, retryable);
            invalid.retry_after = invalidValues[i];
            verify(!Protocol.validClassifiedError(invalid));
        }

        var unavailable = {
            state: "unavailable",
            scope: scope("offline"),
            error: retryable
        };
        verify(Protocol.validProviderSnapshot(unavailable));
        unavailable.error.retry = "manual";
        verify(!Protocol.validProviderSnapshot(unavailable));

        var zeroDuration = readySnapshot("0");
        compare(Protocol.reduceMessage(readyState(), snapshotMessage(1, zeroDuration)).error, "invalid_snapshot");
    }

    function test_executableOverridesAreAbsoluteCanonicalAndBounded() {
        compare(Protocol.bridgeExecutablePath("/home/test/.local/bin/omarchy-ai-bar"), "/home/test/.local/bin/omarchy-ai-bar");
        compare(Protocol.bridgeExecutablePath("omarchy-ai-bar"), "/usr/bin/omarchy-ai-bar");
        compare(Protocol.bridgeExecutablePath("/tmp/../bin/omarchy-ai-bar"), "/usr/bin/omarchy-ai-bar");
        compare(Protocol.bridgeExecutablePath("/tmp//omarchy-ai-bar"), "/usr/bin/omarchy-ai-bar");
        compare(Protocol.bridgeExecutablePath("/tmp/omarchy-ai-bar\n--version"), "/usr/bin/omarchy-ai-bar");
    }

    function test_socketOverrideIsCanonicalBoundedAndTokenized() {
        var socket = "/tmp/oab-private/display.sock";
        compare(Protocol.bridgeSocketPath(""), "");
        compare(Protocol.bridgeSocketPath(socket), socket);
        compare(Protocol.bridgeSocketPath("relative/display.sock"), "");
        compare(Protocol.bridgeSocketPath("/tmp/../display.sock"), "");
        compare(Protocol.bridgeSocketPath("/tmp/display.sock\n--version"), "");
        compare(Protocol.bridgeSocketPath("/" + "x".repeat(Protocol.MAX_SOCKET_PATH_BYTES)), "");
        compare(Protocol.bridgeCommand("/tmp/omarchy-ai-bar", socket), ["/tmp/omarchy-ai-bar", "bridge", "stdio", "--socket", socket]);
        compare(Protocol.bridgeCommand("/tmp/omarchy-ai-bar", ""), ["/tmp/omarchy-ai-bar", "bridge", "stdio"]);
    }

    function test_requestTrackingNeverEvictsOutstandingWork() {
        var state = readyState(["display_snapshots", "action_progress"]);
        for (var requestId = 1; requestId <= Protocol.MAX_TRACKED_REQUESTS; requestId++)
            state = Protocol.registerRequest(state, requestId);
        var saturated = Protocol.registerRequest(state, Protocol.MAX_TRACKED_REQUESTS + 1);
        compare(Protocol.requestProgressState(saturated, 1), "issued");
        compare(Protocol.requestProgressState(saturated, Protocol.MAX_TRACKED_REQUESTS + 1), "");

        var completed = Protocol.reduceMessage(state, {
            type: "action_progress",
            request_id: 1,
            state: "completed"
        });
        verify(completed.accepted);
        var admitted = Protocol.registerRequest(completed.state, Protocol.MAX_TRACKED_REQUESTS + 1);
        compare(Protocol.requestProgressState(admitted, 1), "");
        compare(Protocol.requestProgressState(admitted, Protocol.MAX_TRACKED_REQUESTS + 1), "issued");
    }

    function test_outboundMessagesAreEnumeratedBoundedAndImplemented() {
        var sessionId = Protocol.newSessionId();
        verify(Protocol.validSessionId(sessionId));
        var hello = JSON.parse(Protocol.clientHelloLine(sessionId));
        compare(hello.type, "hello");
        compare(hello.session_id, sessionId);
        verify(hello.capabilities.indexOf("action_progress") !== -1);
        verify(hello.capabilities.indexOf("widget_geometry") === -1);
        verify(hello.capabilities.indexOf("panel_state") === -1);
        compare(Protocol.clientHelloLine("NOT-A-SESSION"), "");

        var refresh = JSON.parse(Protocol.refreshAllLine(9));
        compare(refresh.action.id, "refresh_all");
        compare(Protocol.actionLine(9, "run_shell"), "");
        compare(Protocol.snapshotAckLine(0), "");
    }

    function test_snapshotQuantitiesRemainExactDecimalStrings() {
        var quantity = "18446744073709551615";
        verify(Protocol.isExactDecimalString(quantity));
        verify(!Protocol.isExactDecimalString("18446744073709551616"));

        var result = Protocol.reduceMessage(readyState(), snapshotMessage(1, readySnapshot(quantity)));
        verify(result.accepted);
        compare(typeof result.state.snapshot.snapshots[0].last_known_good.primary.duration_seconds, "string");
        compare(result.state.snapshot.snapshots[0].last_known_good.primary.duration_seconds, quantity);
    }
}
