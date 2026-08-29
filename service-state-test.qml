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
