.pragma library

var MAX_MESSAGE_BYTES = 64 * 1024;
var MAX_EXACT_INTEGER = 9007199254740991;
var MAX_CAPABILITIES = 32;
var MAX_SNAPSHOTS = 256;
var MAX_SNAPSHOT_DEPTH = 32;
var MAX_SNAPSHOT_NODES = 8192;
var MAX_SNAPSHOT_ARRAY_ITEMS = 2048;
var MAX_SNAPSHOT_OBJECT_KEYS = 128;
var MAX_SNAPSHOT_STRING_BYTES = 16 * 1024;
var MAX_TRACKED_REQUESTS = 128;
var MAX_EXECUTABLE_PATH_BYTES = 4096;
var MAX_SOCKET_PATH_BYTES = 103;
var PROTOCOL_MAJOR = 1;
var PROTOCOL_MINOR = 0;

var KNOWN_CAPABILITIES = ["display_snapshots", "provider_accounts", "settings", "runtime_actions", "widget_geometry", "panel_state", "notifications", "action_progress", "compatibility_errors"];

var PROGRESS_STATES = ["queued", "running", "completed", "failed", "cancelled"];
var COMPATIBILITY_CODES = ["unsupported_protocol_major", "hello_required", "protocol_violation"];

var U64_FIELDS = {
    duration_seconds: true,
    input_tokens: true,
    output_tokens: true,
    cache_read_tokens: true,
    cache_creation_tokens: true,
    reasoning_tokens: true,
    priced: true,
    unpriced: true,
    unmetered: true,
    estimated: true,
    retry_after: true,
    total_tokens: true,
    request_count: true,
    standard_tokens: true,
    priority_tokens: true
};

var ERROR_SEMANTICS = {
    missing_credential: ["auth.missing", "Configure credentials for this provider.", "manual", "configure_credential"],
    authentication_expired: ["auth.expired", "Sign in again to continue.", "manual", "reauthenticate"],
    permission_denied: ["auth.permission_denied", "This account does not have permission for this provider.", "manual", "permission_denied"],
    rate_limited: ["provider.rate_limited", "The provider asked us to slow down.", "automatic", "none"],
    provider_unavailable: ["provider.unavailable", "The provider is currently unavailable.", "automatic", "none"],
    network: ["provider.network", "The provider could not be reached.", "automatic", "none"],
    parse: ["provider.parse", "The provider returned an unsupported response.", "never", "none"],
    api: ["provider.api", "The provider returned an unexpected response.", "automatic", "none"]
};

function initialState() {
    return {
        phase: "awaiting_hello",
        compatible: false,
        compatibilityFailure: "",
        protocol: null,
        streamId: "",
        capabilities: [],
        lastSequence: 0,
        snapshot: null,
        lastActionProgress: null,
        lastPongRequestId: 0,
        requestProgress: {},
        requestOrder: []
    };
}

function copyObject(value) {
    var copied = {};
    var keys = Object.keys(value || {});
    for (var i = 0; i < keys.length; i++)
        copied[keys[i]] = value[keys[i]];
    return copied;
}

function cloneState(state, changes) {
    var next = {
        phase: state.phase,
        compatible: state.compatible,
        compatibilityFailure: state.compatibilityFailure,
        protocol: state.protocol,
        streamId: state.streamId,
        capabilities: state.capabilities.slice(0),
        lastSequence: state.lastSequence,
        snapshot: state.snapshot,
        lastActionProgress: state.lastActionProgress,
        lastPongRequestId: state.lastPongRequestId,
        requestProgress: copyObject(state.requestProgress),
        requestOrder: Array.isArray(state.requestOrder) ? state.requestOrder.slice(0) : []
    };
    var keys = Object.keys(changes);
    for (var i = 0; i < keys.length; i++)
        next[keys[i]] = changes[keys[i]];
    return next;
}

function resetRequests(state) {
    return cloneState(state, {
        lastActionProgress: null,
        requestProgress: {},
        requestOrder: []
    });
}

function registerRequest(state, requestId) {
    if (!isObject(state) || !isExactInteger(requestId))
        return state;
    var key = String(requestId);
    if (Object.prototype.hasOwnProperty.call(state.requestProgress || {}, key))
        return state;
    var progress = copyObject(state.requestProgress);
    var order = Array.isArray(state.requestOrder) ? state.requestOrder.slice(0) : [];
    if (order.length >= MAX_TRACKED_REQUESTS) {
        var evictionIndex = -1;
        for (var i = 0; i < order.length; i++) {
            if (["completed", "failed", "cancelled"].indexOf(progress[String(order[i])]) !== -1) {
                evictionIndex = i;
                break;
            }
        }
        if (evictionIndex === -1)
            return state;
        var evicted = order.splice(evictionIndex, 1)[0];
        delete progress[String(evicted)];
    }
    progress[key] = "issued";
    order.push(requestId);
    return cloneState(state, {
        requestProgress: progress,
        requestOrder: order
    });
}

function requestProgressState(state, requestId) {
    if (!isObject(state) || !isExactInteger(requestId))
        return "";
    var progress = state.requestProgress || {};
    var key = String(requestId);
    return Object.prototype.hasOwnProperty.call(progress, key) ? String(progress[key]) : "";
}

function requestIsTerminal(state, requestId) {
    return ["completed", "failed", "cancelled"].indexOf(requestProgressState(state, requestId)) !== -1;
}

function requestIsCompleted(state, requestId) {
    return requestProgressState(state, requestId) === "completed";
}

function validProgressTransition(previous, next) {
    if (previous === "issued")
        return PROGRESS_STATES.indexOf(next) !== -1;
    if (previous === "queued")
        return ["queued", "running", "completed", "failed", "cancelled"].indexOf(next) !== -1;
    if (previous === "running")
        return ["running", "completed", "failed", "cancelled"].indexOf(next) !== -1;
    return previous === next && ["completed", "failed", "cancelled"].indexOf(previous) !== -1;
}

function reconnectingState(state) {
    if (!isObject(state) || typeof state.phase !== "string")
        return initialState();
    return cloneState(state, {
        phase: "awaiting_hello",
        compatible: false,
        compatibilityFailure: "",
        protocol: null,
        capabilities: [],
        lastActionProgress: null,
        lastPongRequestId: 0
    });
}

function outcome(state, accepted, error, stale, messageType, ackSequence, fatal) {
    return {
        state: state,
        accepted: accepted,
        error: error || "",
        stale: stale === true,
        messageType: messageType || "",
        ackSequence: ackSequence || 0,
        fatal: fatal === true
    };
}

function reject(state, error) {
    return outcome(state, false, error, false, "", 0, true);
}

function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, required, optional) {
    if (!isObject(value))
        return false;
    var allowed = required.concat(optional || []);
    var keys = Object.keys(value);
    for (var i = 0; i < required.length; i++) {
        if (!Object.prototype.hasOwnProperty.call(value, required[i]))
            return false;
    }
    for (var j = 0; j < keys.length; j++) {
        if (allowed.indexOf(keys[j]) === -1)
            return false;
    }
    return true;
}

function isExactInteger(value) {
    return typeof value === "number" && isFinite(value) && Math.floor(value) === value && value > 0 && value <= MAX_EXACT_INTEGER;
}

function utf8Length(value) {
    var length = 0;
    for (var i = 0; i < value.length; i++) {
        var code = value.charCodeAt(i);
        if (code <= 0x7f) {
            length += 1;
        } else if (code <= 0x7ff) {
            length += 2;
        } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) {
            length += 4;
            i += 1;
        } else {
            length += 3;
        }
    }
    return length;
}

function validProtocol(value) {
    return hasExactKeys(value, ["major", "minor"]) && typeof value.major === "number" && Math.floor(value.major) === value.major && value.major >= 0 && value.major <= 65535 && typeof value.minor === "number" && Math.floor(value.minor) === value.minor && value.minor >= 0 && value.minor <= 65535;
}

function validCapabilities(value) {
    if (!Array.isArray(value) || value.length > MAX_CAPABILITIES)
        return false;
    var seen = [];
    for (var i = 0; i < value.length; i++) {
        if (typeof value[i] !== "string" || value[i].length === 0 || value[i].length > 64 || !/^[a-z0-9]+(?:_[a-z0-9]+)*$/.test(value[i]) || seen.indexOf(value[i]) !== -1)
            return false;
        seen.push(value[i]);
    }
    return true;
}

function hasCapability(state, capability) {
    return isObject(state) && Array.isArray(state.capabilities) && state.capabilities.indexOf(capability) !== -1;
}

function supportedCapabilities(value) {
    var supported = [];
    for (var i = 0; i < value.length; i++) {
        if (KNOWN_CAPABILITIES.indexOf(value[i]) !== -1)
            supported.push(value[i]);
    }
    return supported;
}

function validSessionId(value) {
    return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

function newSessionId() {
    var value = "";
    for (var i = 0; i < 32; i++)
        value += Math.floor(Math.random() * 16).toString(16);
    return value;
}

function isExactDecimalString(value) {
    return typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value) && (value.length < 20 || value <= "18446744073709551615");
}

function isPositiveExactDecimalString(value) {
    return isExactDecimalString(value) && value !== "0";
}

function validExecutablePath(value) {
    if (typeof value !== "string" || value.length < 2 || value.charAt(0) !== "/" || value.charAt(value.length - 1) === "/" || utf8Length(value) > MAX_EXECUTABLE_PATH_BYTES)
        return false;
    var components = value.split("/");
    for (var i = 1; i < components.length; i++) {
        var component = components[i];
        if (component === "" || component === "." || component === ".." || /[\x00-\x1f\x7f]/.test(component))
            return false;
    }
    return true;
}

function bridgeExecutablePath(overridePath) {
    return validExecutablePath(overridePath) ? overridePath : "/usr/bin/omarchy-ai-bar";
}

function bridgeSocketPath(overridePath) {
    if (overridePath === "")
        return "";
    return validExecutablePath(overridePath) && utf8Length(overridePath) <= MAX_SOCKET_PATH_BYTES ? overridePath : "";
}

function bridgeCommand(executablePath, socketPath) {
    var command = [bridgeExecutablePath(executablePath), "bridge", "stdio"];
    if (bridgeSocketPath(socketPath) !== "")
        command.push("--socket", socketPath);
    return command;
}

function validScope(value) {
    return hasExactKeys(value, ["provider", "instance", "account"]) && typeof value.provider === "string" && value.provider.length > 0 && utf8Length(value.provider) <= 64 && typeof value.instance === "string" && value.instance.length > 0 && utf8Length(value.instance) <= 128 && typeof value.account === "string" && value.account.length > 0 && utf8Length(value.account) <= 160;
}

function sameScope(left, right) {
    return validScope(left) && validScope(right) && left.provider === right.provider && left.instance === right.instance && left.account === right.account;
}

function validOptionalBoundedString(value, maximumBytes) {
    return value === null || (typeof value === "string" && value.length > 0 && utf8Length(value) <= maximumBytes && !/[\x00-\x1f\x7f]/.test(value));
}

function validIdentity(value, scope) {
    if (!hasExactKeys(value, ["scope", "provider_account_id", "email", "organization", "account_label", "plan", "login_method"]) || !sameScope(value.scope, scope))
        return false;
    var fields = ["provider_account_id", "email", "organization", "account_label", "plan", "login_method"];
    for (var i = 0; i < fields.length; i++) {
        if (!validOptionalBoundedString(value[fields[i]], 256))
            return false;
    }
    return true;
}

function validClassifiedError(value) {
    if (!hasExactKeys(value, ["kind", "code", "message", "retry", "auth_implication", "retry_after"]) || typeof value.kind !== "string")
        return false;
    var semantics = ERROR_SEMANTICS[value.kind];
    if (!semantics || value.code !== semantics[0] || value.message !== semantics[1] || value.retry !== semantics[2] || value.auth_implication !== semantics[3])
        return false;
    if (value.retry_after === null)
        return true;
    return value.retry === "automatic" && isPositiveExactDecimalString(value.retry_after);
}

function validWindowUsage(value) {
    if (!isObject(value) || typeof value.state !== "string")
        return false;
    if (value.state === "unknown")
        return hasExactKeys(value, ["state"]);
    return value.state === "known" && hasExactKeys(value, ["state", "used_percent"]) && typeof value.used_percent === "number" && isFinite(value.used_percent);
}

function validRateWindow(value) {
    if (!hasExactKeys(value, ["usage", "duration_seconds", "resets_at", "reset_description", "next_regen_percent", "synthetic_placeholder"]) || !validWindowUsage(value.usage) || (value.duration_seconds !== null && !isPositiveExactDecimalString(value.duration_seconds)) || (value.resets_at !== null && typeof value.resets_at !== "string") || (value.reset_description !== null && typeof value.reset_description !== "string") || (value.next_regen_percent !== null && (typeof value.next_regen_percent !== "number" || !isFinite(value.next_regen_percent))) || typeof value.synthetic_placeholder !== "boolean")
        return false;
    return !value.synthetic_placeholder || (value.usage.state === "known" && value.usage.used_percent === 0);
}

function validFreshness(value) {
    if (!isObject(value) || typeof value.state !== "string")
        return false;
    if (value.state === "fresh" || value.state === "unknown")
        return hasExactKeys(value, ["state"]);
    return value.state === "stale" && hasExactKeys(value, ["state", "since"]) && typeof value.since === "string";
}

function validRefresh(value) {
    if (!isObject(value) || typeof value.state !== "string")
        return false;
    if (value.state === "idle")
        return hasExactKeys(value, ["state"]);
    if (value.state === "scheduled")
        return hasExactKeys(value, ["state", "at"]) && typeof value.at === "string";
    return value.state === "refreshing" && hasExactKeys(value, ["state", "started_at"]) && typeof value.started_at === "string";
}

function validUsageSample(value) {
    if (!hasExactKeys(value, ["scope", "identity", "fetched_at", "primary", "secondary", "tertiary", "extra_windows", "credits", "balance", "cost", "subscription_renews_at", "subscription_expires_at", "reset_credits", "detail_sections", "extensions", "chart_points", "provenance", "confidence", "status"], ["cost_usage"]))
        return false;
    if (!validScope(value.scope) || !validIdentity(value.identity, value.scope) || typeof value.fetched_at !== "string")
        return false;
    for (var laneIndex = 0; laneIndex < 3; laneIndex++) {
        var lane = [value.primary, value.secondary, value.tertiary][laneIndex];
        if (lane !== null && !validRateWindow(lane))
            return false;
    }
    if (!Array.isArray(value.extra_windows) || value.extra_windows.length > 16)
        return false;
    for (var windowIndex = 0; windowIndex < value.extra_windows.length; windowIndex++) {
        var named = value.extra_windows[windowIndex];
        if (!hasExactKeys(named, ["id", "title", "window"]) || typeof named.id !== "string" || typeof named.title !== "string" || !validRateWindow(named.window))
            return false;
    }
    // The Rust stdio bridge performs the complete domain deserialization and
    // invariant round-trip. QML repeats the schema it directly renders and
    // bounds every delegated subtree so presentation never becomes a second
    // provider parser.
    if ((value.credits !== null && !isObject(value.credits)) || (value.balance !== null && !isObject(value.balance)) || (value.cost !== null && !isObject(value.cost)) || (value.cost_usage !== undefined && !isObject(value.cost_usage)) || (value.reset_credits !== null && !isObject(value.reset_credits)) || !Array.isArray(value.detail_sections) || value.detail_sections.length > 8 || !Array.isArray(value.extensions) || value.extensions.length > 8 || !Array.isArray(value.chart_points) || value.chart_points.length > 120 || !Array.isArray(value.provenance) || value.provenance.length > 16 || ["exact", "estimated", "percentOnly", "unknown"].indexOf(value.confidence) === -1 || !isObject(value.status))
        return false;
    return (value.subscription_renews_at === null || typeof value.subscription_renews_at === "string") && (value.subscription_expires_at === null || typeof value.subscription_expires_at === "string");
}

function validProviderSnapshot(value) {
    if (!isObject(value) || typeof value.state !== "string")
        return false;
    if (value.state === "loading")
        return hasExactKeys(value, ["state", "scope"]) && validScope(value.scope);
    if (value.state === "unavailable")
        return hasExactKeys(value, ["state", "scope", "error"]) && validScope(value.scope) && validClassifiedError(value.error);
    if (value.state !== "ready" || !hasExactKeys(value, ["state", "last_known_good", "freshness", "refresh", "error"]) || !validUsageSample(value.last_known_good) || !validFreshness(value.freshness) || !validRefresh(value.refresh) || (value.error !== null && !validClassifiedError(value.error)))
        return false;
    return value.error === null || value.freshness.state === "stale";
}

function validSnapshotTree(value, depth, budget, fieldName) {
    if (depth > MAX_SNAPSHOT_DEPTH || budget.nodes >= MAX_SNAPSHOT_NODES)
        return false;
    budget.nodes += 1;
    if (value === null)
        return true;

    if (fieldName && U64_FIELDS[fieldName] === true)
        return isExactDecimalString(value);

    var kind = typeof value;
    if (kind === "boolean")
        return true;
    if (kind === "string")
        return utf8Length(value) <= MAX_SNAPSHOT_STRING_BYTES;
    if (kind === "number") {
        if (!isFinite(value))
            return false;
        if (value === 0 && 1 / value === -Infinity)
            return false;
        return Math.floor(value) !== value || Math.abs(value) <= MAX_EXACT_INTEGER;
    }
    if (kind !== "object")
        return false;

    if (Array.isArray(value)) {
        if (value.length > MAX_SNAPSHOT_ARRAY_ITEMS)
            return false;
        for (var itemIndex = 0; itemIndex < value.length; itemIndex++) {
            if (!validSnapshotTree(value[itemIndex], depth + 1, budget, ""))
                return false;
        }
        return true;
    }

    var keys = Object.keys(value);
    if (keys.length > MAX_SNAPSHOT_OBJECT_KEYS)
        return false;
    for (var keyIndex = 0; keyIndex < keys.length; keyIndex++) {
        var key = keys[keyIndex];
        if (key === "__proto__" || key === "prototype" || key === "constructor")
            return false;
        if (!validSnapshotTree(value[key], depth + 1, budget, key))
            return false;
    }
    return true;
}

function validSnapshotEnvelope(value) {
    if (!hasExactKeys(value, ["schema_version", "generated_at", "snapshots"], ["privacy"]))
        return false;
    if (value.schema_version !== 1)
        return false;
    if (typeof value.generated_at !== "string" || value.generated_at.length === 0 || value.generated_at.length > 64)
        return false;
    if (value.privacy !== undefined && value.privacy !== "redacted")
        return false;
    if (!Array.isArray(value.snapshots) || value.snapshots.length > MAX_SNAPSHOTS)
        return false;
    if (!validSnapshotTree(value, 0, {
        nodes: 0
    }, ""))
        return false;
    for (var i = 0; i < value.snapshots.length; i++) {
        if (!validProviderSnapshot(value.snapshots[i]))
            return false;
    }
    return true;
}

function hasCanonicalOuterInteger(raw, field, value) {
    var marker = "\"" + field + "\":";
    var index = raw.indexOf(marker);
    if (index === -1 || raw.indexOf(marker, index + marker.length) !== -1)
        return false;
    var start = index + marker.length;
    var end = start;
    while (end < raw.length && raw.charCodeAt(end) >= 48 && raw.charCodeAt(end) <= 57)
        end += 1;
    var lexical = raw.slice(start, end);
    var terminator = raw.charAt(end);
    return (terminator === "," || terminator === "}") && /^[1-9][0-9]*$/.test(lexical) && lexical === String(value);
}

function compatibilityState(state, code, supported) {
    return cloneState(state, {
        phase: "incompatible",
        compatible: false,
        compatibilityFailure: code,
        protocol: supported,
        capabilities: [],
        snapshot: null,
        requestProgress: {},
        requestOrder: []
    });
}

function reduceMessage(state, message) {
    if (!isObject(state) || typeof state.phase !== "string")
        state = initialState();
    if (!isObject(message) || typeof message.type !== "string")
        return reject(state, "invalid_message");

    if (message.type === "compatibility_error") {
        if (!hasExactKeys(message, ["type", "code", "supported"]) || COMPATIBILITY_CODES.indexOf(message.code) === -1 || !validProtocol(message.supported))
            return reject(state, "invalid_compatibility_error");
        return outcome(compatibilityState(state, message.code, message.supported), true, "", false, message.type);
    }

    if (state.phase === "awaiting_hello") {
        if (message.type !== "hello")
            return reject(state, "hello_required");
        if (!hasExactKeys(message, ["type", "protocol", "stream_id", "capabilities"]) || !validProtocol(message.protocol) || !validSessionId(message.stream_id) || !validCapabilities(message.capabilities))
            return reject(state, "invalid_hello");
        if (message.protocol.major !== PROTOCOL_MAJOR) {
            return outcome(compatibilityState(state, "unsupported_protocol_major", {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR
            }), true, "", false, message.type);
        }
        if (message.capabilities.indexOf("display_snapshots") === -1) {
            return outcome(compatibilityState(state, "missing_display_snapshots", message.protocol), true, "", false, message.type);
        }
        var streamChanged = state.streamId !== "" && state.streamId !== message.stream_id;
        return outcome(cloneState(state, {
            phase: "ready",
            compatible: true,
            compatibilityFailure: "",
            protocol: message.protocol,
            streamId: message.stream_id,
            capabilities: supportedCapabilities(message.capabilities),
            lastSequence: streamChanged ? 0 : state.lastSequence,
            snapshot: streamChanged ? null : state.snapshot,
            lastActionProgress: streamChanged ? null : state.lastActionProgress,
            requestProgress: streamChanged ? {} : copyObject(state.requestProgress),
            requestOrder: streamChanged || !Array.isArray(state.requestOrder) ? [] : state.requestOrder.slice(0)
        }), true, "", false, message.type);
    }

    if (state.phase !== "ready")
        return reject(state, "connection_incompatible");

    if (message.type === "hello")
        return reject(state, "duplicate_hello");

    if (message.type === "snapshot") {
        if (!hasCapability(state, "display_snapshots"))
            return reject(state, "capability_not_negotiated");
        if (!hasExactKeys(message, ["type", "sequence", "snapshot"]) || !isExactInteger(message.sequence) || !validSnapshotEnvelope(message.snapshot))
            return reject(state, "invalid_snapshot");
        if (message.sequence === state.lastSequence) {
            return outcome(state, false, "", true, message.type, message.sequence);
        }
        if (message.sequence < state.lastSequence) {
            return outcome(state, false, "", true, message.type);
        }
        return outcome(cloneState(state, {
            lastSequence: message.sequence,
            snapshot: message.snapshot
        }), true, "", false, message.type, message.sequence);
    }

    if (message.type === "action_progress") {
        if (!hasCapability(state, "action_progress"))
            return reject(state, "capability_not_negotiated");
        if (!hasExactKeys(message, ["type", "request_id", "state"]) || !isExactInteger(message.request_id) || PROGRESS_STATES.indexOf(message.state) === -1)
            return reject(state, "invalid_action_progress");
        var previousProgress = requestProgressState(state, message.request_id);
        if (previousProgress === "")
            return reject(state, "unsolicited_action_progress");
        if (!validProgressTransition(previousProgress, message.state))
            return reject(state, "invalid_action_progress_transition");
        var progress = copyObject(state.requestProgress);
        progress[String(message.request_id)] = message.state;
        return outcome(cloneState(state, {
            lastActionProgress: {
                request_id: message.request_id,
                state: message.state
            },
            requestProgress: progress
        }), true, "", false, message.type);
    }

    if (message.type === "pong") {
        if (!hasExactKeys(message, ["type", "request_id"]) || !isExactInteger(message.request_id))
            return reject(state, "invalid_pong");
        return outcome(cloneState(state, {
            lastPongRequestId: message.request_id
        }), true, "", false, message.type);
    }

    return reject(state, "unknown_message_type");
}

function reduceLine(state, line) {
    var raw = String(line);
    if (raw.length === 0 || raw.indexOf("\n") !== -1 || raw.indexOf("\r") !== -1 || utf8Length(raw) + 1 > MAX_MESSAGE_BYTES)
        return reject(state, "invalid_frame");
    var message;
    try {
        message = JSON.parse(raw);
    } catch (error) {
        return reject(state, "malformed_json");
    }
    if (!isObject(message))
        return reject(state, "invalid_message");
    if ((message.type === "snapshot" && !hasCanonicalOuterInteger(raw, "sequence", message.sequence)) || ((message.type === "action_progress" || message.type === "pong") && !hasCanonicalOuterInteger(raw, "request_id", message.request_id)))
        return reject(state, "noncanonical_integer");
    return reduceMessage(state, message);
}

function clientHelloLine(sessionId) {
    if (!validSessionId(sessionId))
        return "";
    return JSON.stringify({
        type: "hello",
        protocol: {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR
        },
        bridge_version: {
            major: 0,
            minor: 1,
            patch: 0
        },
        session_id: sessionId,
        capabilities: ["display_snapshots", "runtime_actions", "action_progress", "compatibility_errors"]
    }) + "\n";
}

function snapshotAckLine(sequence) {
    if (!isExactInteger(sequence))
        return "";
    return JSON.stringify({
        type: "snapshot_ack",
        sequence: sequence
    }) + "\n";
}

function actionLine(requestId, actionId) {
    if (!isExactInteger(requestId) || ["open_panel", "close_panel", "refresh_all"].indexOf(actionId) === -1)
        return "";
    return JSON.stringify({
        type: "action",
        request_id: requestId,
        action: {
            id: actionId
        }
    }) + "\n";
}

function openPanelLine(requestId) {
    return actionLine(requestId, "open_panel");
}

function closePanelLine(requestId) {
    return actionLine(requestId, "close_panel");
}

function refreshAllLine(requestId) {
    return actionLine(requestId, "refresh_all");
}
