import QtQuick
import qs.Commons

Item {
    id: root

    property var metric: null
    property var panelRoot: null
    property color foreground: Color.foreground
    property color muted: Qt.darker(foreground, 1.55)
    property color accent: Color.accent
    property string fontFamily: Style.font.family
    property int warningThreshold: 90
    property bool showResetTimes: true
    property bool showPace: true
    property bool showWarningMarkers: true
    property bool showWorkdayTicks: true
    property int clockTick: 0

    readonly property bool known: metric && metric.known === true
    readonly property bool syntheticPlaceholder: metric && metric.syntheticPlaceholder === true
    readonly property real usedPercent: known ? clampPercent(metric.percent) : 0
    readonly property real displayedPercent: displayPercent(usedPercent)
    readonly property real idealUsedPercent: idealPercent()
    readonly property string paceText: showPace ? paceLabel() : ""
    readonly property string reserveText: showPace ? reserveLabel() : ""
    readonly property string runsOutText: showPace ? runsOutLabel() : ""
    readonly property string nextRegenText: nextRegenLabel()
    readonly property var workdayMarkers: workdayMarkerValues()
    readonly property bool hasMeta: (showResetTimes && metric && String(metric.reset || "") !== "") || paceText !== "" || reserveText !== ""

    implicitHeight: metricColumn.implicitHeight

    function clampPercent(value) {
        return Math.max(0, Math.min(100, Number(value || 0)));
    }

    function displayPercent(value) {
        if (panelRoot && typeof panelRoot.displayPercent === "function")
            return panelRoot.displayPercent(value);
        return clampPercent(value);
    }

    function markerPosition(value) {
        return clampPercent(displayPercent(value));
    }

    function durationSeconds() {
        var value = metric ? Number(metric.durationSeconds || 0) : 0;
        return isFinite(value) && value > 0 ? value : 0;
    }

    function resetMilliseconds() {
        var parsed = new Date(metric ? String(metric.resetsAt || "") : "");
        return isNaN(parsed.getTime()) ? 0 : parsed.getTime();
    }

    function idealPercent() {
        // clockTick intentionally participates so the forecast advances while the menu is open.
        var tick = clockTick;
        var duration = durationSeconds();
        var reset = resetMilliseconds();
        if (!known || syntheticPlaceholder || duration <= 0 || reset <= 0)
            return -1;
        var now = Date.now();
        var start = reset - duration * 1000;
        if (now <= start || now >= reset)
            return -1;
        return clampPercent((now - start) / (duration * 1000) * 100);
    }

    function paceLabel() {
        if (idealUsedPercent < 0)
            return "";
        var delta = usedPercent - idealUsedPercent;
        if (Math.abs(delta) <= 2)
            return "On pace";
        return Math.round(Math.abs(delta)) + (delta > 0 ? "% in deficit" : "% in reserve");
    }

    function projectedUsedPercent() {
        if (idealUsedPercent < 5 || usedPercent <= 0)
            return -1;
        return usedPercent / (idealUsedPercent / 100);
    }

    function reserveLabel() {
        var projected = projectedUsedPercent();
        if (projected < 0)
            return "";
        if (projected <= 100)
            return "Lasts until reset";
        return "";
    }

    function relativeDuration(milliseconds) {
        var minutes = Math.max(0, Math.floor(milliseconds / 60000));
        if (minutes < 60)
            return "in " + Math.max(1, minutes) + "m";
        var hours = Math.floor(minutes / 60);
        if (hours < 48)
            return "in " + hours + "h " + (minutes % 60) + "m";
        return "in " + Math.floor(hours / 24) + "d " + (hours % 24) + "h";
    }

    function runsOutLabel() {
        var projected = projectedUsedPercent();
        var duration = durationSeconds();
        var reset = resetMilliseconds();
        if (duration <= 0 || reset <= 0 || usedPercent <= 0)
            return "";
        var sessionWindow = duration <= 21600;
        if (usedPercent >= 100)
            return sessionWindow ? "Projected empty now" : "Runs out now";
        if (projected <= 100)
            return "";
        var start = reset - duration * 1000;
        var elapsed = Date.now() - start;
        if (elapsed <= 0)
            return "";
        var runOutAt = start + elapsed * (100 / usedPercent);
        if (runOutAt >= reset)
            return "";
        if (runOutAt <= Date.now())
            return sessionWindow ? "Projected empty now" : "Runs out now";
        return (sessionWindow ? "Projected empty " : "Runs out ") + relativeDuration(runOutAt - Date.now());
    }

    function nextRegenLabel() {
        if (!metric || metric.nextRegenPercent === null || metric.nextRegenPercent === undefined)
            return "";
        var value = Number(metric.nextRegenPercent);
        if (!isFinite(value))
            return "";
        var rounded = Math.round(value);
        return "Next regen " + (rounded > 0 ? "+" : "") + rounded + "%";
    }

    function workdayMarkerValues() {
        var duration = durationSeconds();
        if (!showWorkdayTicks || duration < 5 * 86400 || duration > 8 * 86400)
            return [];
        return [20, 40, 60, 80];
    }

    Timer {
        interval: 60000
        repeat: true
        running: root.visible && root.showPace
        onTriggered: root.clockTick += 1
    }

    Column {
        id: metricColumn
        width: parent.width
        spacing: Style.space(4)

        Row {
            width: parent.width

            Text {
                width: parent.width - metricValue.width
                text: root.metric ? String(root.metric.title || "Quota") : "Quota"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                elide: Text.ElideRight
            }

            Text {
                id: metricValue
                text: root.known && root.panelRoot ? root.panelRoot.percentageLabel(root.usedPercent) : (root.known ? Math.round(root.displayedPercent) + "%" : "Unavailable")
                color: !root.showResetTimes && root.paceText.indexOf("deficit") !== -1 ? Color.urgent : root.muted
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
            }
        }

        Rectangle {
            id: barTrack
            width: parent.width
            height: Style.space(7)
            radius: height / 2
            color: Style.normalFillFor(root.foreground, root.accent)
            opacity: root.known ? 1 : 0.55

            Rectangle {
                width: parent.width * root.displayedPercent / 100
                height: parent.height
                radius: parent.radius
                visible: root.known
                color: root.usedPercent >= root.warningThreshold ? Color.urgent : root.accent
            }

            Repeater {
                model: root.workdayMarkers

                delegate: Rectangle {
                    required property real modelData
                    x: Math.max(0, Math.min(barTrack.width - width, barTrack.width * root.markerPosition(modelData) / 100))
                    y: 1
                    width: 1
                    height: barTrack.height - 2
                    color: root.foreground
                    opacity: 0.28
                }
            }

            Rectangle {
                x: Math.max(0, Math.min(parent.width - width, parent.width * root.markerPosition(root.idealUsedPercent) / 100))
                y: -2
                width: 2
                height: parent.height + 4
                radius: 1
                visible: root.showPace && root.idealUsedPercent >= 0
                color: root.foreground
                opacity: 0.72
            }

            Rectangle {
                x: Math.max(0, Math.min(parent.width - width, parent.width * root.markerPosition(root.warningThreshold) / 100))
                y: -1
                width: 2
                height: parent.height + 2
                radius: 1
                visible: root.showWarningMarkers && root.known
                color: Color.urgent
                opacity: 0.9
            }
        }

        Row {
            width: parent.width
            visible: root.hasMeta

            Text {
                width: parent.width - paceMeta.width
                text: root.showResetTimes && root.metric && String(root.metric.reset || "") !== "" ? "Resets " + root.metric.reset : root.paceText
                color: root.muted
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
            }

            Text {
                id: paceMeta
                text: root.showResetTimes && root.metric && String(root.metric.reset || "") !== "" ? [root.paceText, root.reserveText].filter(function (value) {
                    return value !== "";
                }).join(" · ") : root.reserveText
                color: root.paceText.indexOf("deficit") !== -1 ? Color.urgent : root.muted
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideLeft
            }
        }

        Text {
            width: parent.width
            visible: root.syntheticPlaceholder || root.runsOutText !== "" || root.nextRegenText !== ""
            text: root.syntheticPlaceholder ? "Waiting for the first usage update" : [root.runsOutText, root.nextRegenText].filter(function (value) {
                return value !== "";
            }).join(" · ")
            color: root.runsOutText !== "" ? Color.urgent : root.muted
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
        }
    }
}
