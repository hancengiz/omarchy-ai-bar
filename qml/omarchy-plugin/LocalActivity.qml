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

    readonly property var history: row ? row.localHistory : null
    readonly property var costUsage: row ? row.costUsage : null
    readonly property string message: service ? service.localHistoryMessage(row) : ""
    readonly property bool machine: history && history.scope === "machine"
    readonly property bool canUseMachine: row && row.provider === "codex" && history && history.scope === "account" && history.state === "empty"

    spacing: Style.space(9)
    visible: row && (row.historySupported || costUsage)

    PanelSeparator {
        width: parent.width
        foreground: root.foreground
    }

    Text {
        width: parent.width
        text: root.history ? (root.machine ? "THIS MACHINE · LOCAL ACTIVITY" : "THIS ACCOUNT · LOCAL ACTIVITY") : "LOCAL ACTIVITY"
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 0.8
        wrapMode: Text.WordWrap
    }

    Text {
        width: parent.width
        visible: root.message !== ""
        text: root.message
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

    Text {
        width: parent.width
        visible: root.machine && root.row && root.row.provider === "codex"
        text: "Activity from this machine's native Codex sessions. It is independent of the quota account above."
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
    }

    Text {
        width: parent.width
        visible: root.costUsage !== null && root.costUsage.updated_at !== undefined
        text: root.costUsage ? "History updated " + String(root.costUsage.updated_at || "").replace("T", " ").replace("Z", " UTC") : ""
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
    }

    Grid {
        id: stats
        width: parent.width
        columns: 2
        columnSpacing: Style.space(12)
        rowSpacing: Style.space(7)
        visible: root.costUsage !== null

        Repeater {
            model: root.row ? root.row.costStats || [] : []
            delegate: Column {
                required property var modelData
                width: (stats.width - stats.columnSpacing) / 2
                Text {
                    width: parent.width
                    text: modelData.label
                    color: root.muted
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                }
                Text {
                    text: modelData.value
                    color: root.foreground
                    font.family: Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                }
            }
        }
    }

    Row {
        spacing: Style.space(6)
        visible: root.costUsage !== null
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

    InlineChart {
        width: parent.width
        chart: root.service ? root.service.costChartFrom(root.costUsage, root.metric) : null
        foreground: root.foreground
        muted: root.muted
        accent: root.accent
    }

    Text {
        width: parent.width
        visible: root.costUsage !== null
        text: root.row ? root.row.costCaption || "" : ""
        color: root.muted
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
    }
}
