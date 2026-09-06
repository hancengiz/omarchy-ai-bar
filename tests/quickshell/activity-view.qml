import QtQuick
import QtQuick.Window
import Quickshell
import "Plugin" as Plugin

ShellRoot {
    id: test

    property int phase: 0
    property bool failed: false
    property var row: ({
            provider: "claude",
            historySupported: true,
            localHistory: {
                scope: "machine",
                state: "scanning",
                data: null
            },
            costUsage: null
        })
    readonly property var data: ({
            unit: {
                kind: "currency",
                code: "USD"
            },
            updated_at: "2026-09-06T07:11:59.790571726Z",
            history_days: 3,
            history_coverage_established: true,
            session: {
                amount: null,
                total_tokens: "0"
            },
            history: {
                amount: "1.50",
                total_tokens: "5240000",
                coverage: {
                    unpriced: "1"
                }
            },
            daily: [
                {
                    day: "2026-09-05",
                    metrics: {
                        amount: "1.50",
                        total_tokens: "5240000",
                        coverage: {
                            unpriced: "1"
                        }
                    }
                }
            ]
        })

    Plugin.Service {
        id: backend
        bridgeEnabled: false
    }

    Window {
        visible: true
        width: 360
        height: 640
        Item {
            id: host
            width: 360
            visible: false

            Repeater {
                id: activityRepeater
                model: [test.row]
                delegate: Plugin.LocalActivity {
                    required property var modelData
                    width: host.width
                    service: backend
                    row: modelData
                }
            }
        }
    }

    function check(condition, message) {
        if (!condition) {
            failed = true;
            console.log("OAB_ACTIVITY_VIEW_TEST_FAIL", message);
        }
    }

    function findChart(item) {
        if (item.chart !== undefined)
            return item;
        for (var i = 0; i < item.children.length; i++) {
            var found = findChart(item.children[i]);
            if (found)
                return found;
        }
        return null;
    }

    Timer {
        interval: 100
        running: true
        repeat: true
        onTriggered: {
            var activity = activityRepeater.itemAt(0);
            var chart = test.findChart(activity);
            if (test.phase === 0) {
                test.check(activity.emptyMessage === "Loading activity…", "loading should have one short status");
                test.row = {
                    provider: "claude",
                    historySupported: true,
                    localHistory: {
                        scope: "machine",
                        state: "ready",
                        data: test.data
                    },
                    costUsage: test.data
                };
            } else if (test.phase === 1) {
                host.visible = true;
            } else if (test.phase === 2) {
                test.check(chart && chart.points.length === 3 && chart.visible && chart.height > 80, "history chart must appear after data arrives in a closed popup");
                test.check(activity.emptyMessage === "" && !activity.detailsExpanded, "loaded history should not show status prose or expanded details");
                test.check(activity.total(test.data.history) === "5.24M", "token total must remain available with incomplete pricing");
                activity.metric = "cost";
            } else if (test.phase === 3) {
                test.check(chart.points[1].value === null, "unpriced cost must not become zero");
                test.check(activity.total(test.data.session) === "—", "missing cost must not become zero");
                host.visible = false;
            } else if (test.phase === 4) {
                host.visible = true;
            } else {
                test.check(chart.visible && chart.height > 80, "reopening the popup must preserve the chart");
                console.log(test.failed ? "OAB_ACTIVITY_VIEW_TEST_FAIL" : "OAB_ACTIVITY_VIEW_TEST_PASS");
                Qt.quit();
            }
            test.phase++;
        }
    }
}
