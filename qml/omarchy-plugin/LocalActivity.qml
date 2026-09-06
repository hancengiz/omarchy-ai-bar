import QtQuick
import qs.Commons
import qs.Ui

Column {
    id: root

    property var row: null
    property var service: null
    property color foreground: Color.foreground
    property color muted: Qt.darker(foreground, 1.55)
    property color accent: Color.accent
    property string metric: "tokens"
    property bool detailsExpanded: false

    readonly property var history: row ? row.localHistory : null
    readonly property var costUsage: row ? row.costUsage : null
    readonly property bool hasData: !!costUsage
    readonly property bool machine: history && history.scope === "machine"
    readonly property bool canUseMachine: row && row.provider === "codex" && history && history.scope === "account" && history.state === "empty"
    readonly property bool partialPricing: hasData && costUsage.history && costUsage.history.coverage && Number(costUsage.history.coverage.unpriced || 0) > 0
    readonly property string emptyMessage: {
        if (hasData)
            return "";
        if (!history || history.state === "scanning")
            return "Loading activity…";
        if (history.state === "failed")
            return "Activity unavailable. Try refreshing.";
        return machine ? "No recent activity on this machine." : "No activity for this account.";
    }

    function total(metrics) {
        if (!metrics || !service)
            return "—";
        var value = metric === "cost" ? metrics.amount : metrics.total_tokens;
        if (value === null || value === undefined)
            return "—";
        return metric === "cost" ? service.formatAmount(costUsage, value) : service.compactQuantity(value);
    }

    spacing: Style.space(8)
    visible: row && (row.historySupported || costUsage)

    PanelSeparator {
        width: parent.width
        foreground: root.foreground
    }

    Row {
        width: parent.width
        Text {
            width: parent.width - scopeLabel.implicitWidth
            text: "Local activity"
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            font.bold: true
        }
        Text {
            id: scopeLabel
            text: root.history ? (root.machine ? "This machine" : "This account") : ""
            color: root.muted
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
        }
    }

    Text {
        width: parent.width
        visible: root.emptyMessage !== ""
        text: root.emptyMessage
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
    }

    Button {
        visible: root.canUseMachine
        text: "Show this machine's activity"
        foreground: root.foreground
        focusable: true
        enabled: root.service && !root.service.providerConfigBusy
        onClicked: root.service.setProviderOption("codex", "codex-local-session-cost-ledger", true)
    }

    Row {
        spacing: Style.space(6)
        visible: root.hasData
        Repeater {
            model: ["tokens", "cost"]
            delegate: Button {
                required property string modelData
                text: modelData === "tokens" ? "Tokens" : "Cost"
                foreground: root.foreground
                focusable: true
                selected: root.metric === modelData
                accent: root.accent
                color: selected ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.16) : "transparent"
                bordered: true
                onClicked: root.metric = modelData
            }
        }
    }

    Row {
        width: parent.width
        spacing: Style.space(12)
        visible: root.hasData
        Repeater {
            model: ["session", "history"]
            delegate: Column {
                required property string modelData
                width: (root.width - Style.space(12)) / 2
                spacing: Style.space(3)
                Text {
                    text: modelData === "session" ? "Today" : "Last " + String(root.costUsage ? root.costUsage.history_days || 30 : 30) + " days"
                    color: root.muted
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                }
                Text {
                    text: root.total(root.costUsage ? root.costUsage[modelData] : null)
                    color: root.foreground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.body
                    font.bold: true
                }
            }
        }
    }

    Text {
        width: parent.width
        visible: root.hasData && root.metric === "cost"
        text: root.partialPricing ? "Estimated cost · some usage is unpriced" : "Estimated cost"
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
    }

    InlineChart {
        width: parent.width
        chart: root.service ? root.service.costChartFrom(root.costUsage, root.metric) : null
        compact: true
        foreground: root.foreground
        muted: root.muted
        accent: root.accent
    }

    Button {
        visible: root.hasData
        text: root.detailsExpanded ? "Hide details" : "Details"
        foreground: root.muted
        focusable: true
        onClicked: root.detailsExpanded = !root.detailsExpanded
    }

    Text {
        width: parent.width
        visible: root.hasData && root.detailsExpanded
        text: {
            var parts = [];
            if (root.machine && root.row && root.row.provider === "codex")
                parts.push("Includes this machine's Codex sessions across accounts.");
            if (root.history && root.history.state === "scanning")
                parts.push("Updating activity…");
            else if (root.history && root.history.state === "failed")
                parts.push("Refresh failed. Showing previous activity.");
            if (root.row && root.row.costCaption)
                parts.push(root.row.costCaption);
            if (root.costUsage && root.costUsage.updated_at) {
                var date = new Date(String(root.costUsage.updated_at).replace(/(\.\d{3})\d+/, "$1"));
                if (!isNaN(date.getTime()))
                    parts.push("Updated " + Qt.formatDateTime(date, "d MMM, HH:mm"));
            }
            return parts.join("\n");
        }
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
    }
}
