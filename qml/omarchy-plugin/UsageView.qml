import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Item {
    id: view

    property var panelRoot: null
    property alias scrollArea: usageScroll
    property var expandedErrors: ({})
    property int relativeClockTick: 0

    readonly property color foreground: panelRoot ? panelRoot.foreground : Color.foreground
    readonly property color muted: panelRoot ? panelRoot.muted : Qt.darker(foreground, 1.55)
    readonly property var providers: panelRoot ? panelRoot.configuredRows : []

    readonly property string selectedProvider: {
        var saved = String(setting("selectedProviderTab", ""));
        for (var i = 0; i < providers.length; i++) {
            if (providers[i].provider === saved)
                return saved;
        }
        return providers.length ? providers[0].provider : "";
    }
    readonly property var visibleProviders: setting("providerLayout", "List") === "Tabs" ? providers.filter(function (row) {
        return row.provider === view.selectedProvider;
    }) : providers

    function fontFamily() {
        return panelRoot && panelRoot.bar ? panelRoot.bar.fontFamily : Style.font.family;
    }

    function setting(key, fallback) {
        return panelRoot ? panelRoot.setting(key, fallback) : fallback;
    }

    function relativeUpdated(value) {
        // Bind the relative label to the minute timer so an open popup advances from
        // "just now" to "1m ago" without waiting for another daemon snapshot.
        var now = Date.now() + relativeClockTick * 0;
        var parsed = new Date(String(value || ""));
        if (isNaN(parsed.getTime()))
            return "";
        var seconds = Math.max(0, Math.floor((now - parsed.getTime()) / 1000));
        if (seconds < 60)
            return "just now";
        if (seconds < 3600)
            return Math.floor(seconds / 60) + "m ago";
        if (seconds < 86400)
            return Math.floor(seconds / 3600) + "h ago";
        return Qt.formatDateTime(parsed, "ddd HH:mm");
    }

    function accentForProvider(provider) {
        // CodexBar's shipped flagship palette. Providers outside this focused slice
        // keep the active Omarchy theme accent.
        var colors = {
            codex: [73, 163, 176],
            claude: [204, 124, 94],
            grok: [16, 163, 127],
            copilot: [168, 85, 247],
            zai: [232, 90, 106]
        };
        var rgb = colors[String(provider || "")];
        return rgb ? Qt.rgba(rgb[0] / 255, rgb[1] / 255, rgb[2] / 255, 1) : Color.accent;
    }

    function privateText(value) {
        return panelRoot && typeof panelRoot.privacyText === "function" ? panelRoot.privacyText(value) : String(value || "");
    }

    function isErrorExpanded(provider) {
        return expandedErrors[String(provider || "")] === true;
    }

    function toggleError(provider) {
        var key = String(provider || "");
        var next = {};
        for (var existing in expandedErrors)
            next[existing] = expandedErrors[existing];
        next[key] = !isErrorExpanded(key);
        expandedErrors = next;
    }

    function copyText(value) {
        clipboardProxy.text = privateText(value);
        clipboardProxy.selectAll();
        clipboardProxy.copy();
        clipboardProxy.deselect();
    }

    function noticeText(provider) {
        if (!provider)
            return "";
        var error = String(provider.errorMessage || "");
        if (provider.ready && error !== "")
            return "Showing last known usage · " + error;
        if (error !== "")
            return error;
        if (provider.stale)
            return "Showing last known usage · data is stale";
        return String(provider.status || "");
    }

    TextEdit {
        id: clipboardProxy
        visible: false
        readOnly: true
    }

    Timer {
        interval: 60000
        repeat: true
        running: view.visible
        onTriggered: view.relativeClockTick += 1
    }

    Flickable {
        id: usageScroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: usageColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
        }

        Column {
            id: usageColumn
            width: usageScroll.width
            spacing: Style.space(10)

            BorderSurface {
                width: parent.width
                implicitHeight: emptyColumn.implicitHeight + Style.space(28)
                visible: view.providers.length === 0
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.controlSpec("normal", view.foreground, Color.accent)
                radius: Style.cornerRadius

                Column {
                    id: emptyColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(32)
                    spacing: Style.space(8)

                    Text {
                        width: parent.width
                        text: "No connected providers"
                        horizontalAlignment: Text.AlignHCenter
                        color: view.foreground
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.body
                        font.bold: true
                    }

                    Text {
                        width: parent.width
                        text: "Detected providers appear in Settings. Enable and sign in to one to show its quota here."
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.WordWrap
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.bodySmall
                    }

                    Button {
                        anchors.horizontalCenter: parent.horizontalCenter
                        text: "Open Settings"
                        foreground: view.foreground
                        focusable: true
                        onClicked: if (view.panelRoot)
                            view.panelRoot.openSettings()
                    }
                }
            }

            Flow {
                width: parent.width
                spacing: Style.space(6)
                visible: view.setting("providerLayout", "List") === "Tabs" && view.providers.length > 1
                Repeater {
                    model: view.providers
                    delegate: Button {
                        required property var modelData
                        text: modelData.label
                        foreground: view.foreground
                        focusable: true
                        enabled: view.selectedProvider !== modelData.provider
                        onClicked: view.panelRoot.persistSetting("selectedProviderTab", modelData.provider)
                    }
                }
            }

            Repeater {
                model: view.visibleProviders

                delegate: Column {
                    id: providerGroup
                    required property var modelData
                    width: usageColumn.width
                    spacing: Style.space(8)

                    Repeater {
                        model: view.panelRoot && view.panelRoot.service ? view.panelRoot.service.subscriptionRows(providerGroup.modelData, view.setting("accountLayout", view.setting("codexAccountLayout", "Tabs"))) : [providerGroup.modelData]
                        delegate: BorderSurface {
                            id: providerSurface
                            required property var modelData
                            readonly property color providerAccent: view.accentForProvider(modelData.provider)
                            width: usageColumn.width
                            implicitHeight: cardColumn.implicitHeight + Style.space(22)
                            color: Style.normalFillFor(view.foreground, Color.accent)
                            borderSpec: Border.controlSpec("normal", view.foreground, Color.accent)
                            radius: Style.cornerRadius

                            Column {
                                id: cardColumn
                                anchors.centerIn: parent
                                width: parent.width - Style.space(24)
                                spacing: Style.space(8)

                                Row {
                                    width: parent.width

                                    Text {
                                        width: parent.width - accountLabel.width
                                        text: providerSurface.modelData.label
                                        color: view.foreground
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.body
                                        font.bold: true
                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        id: accountLabel
                                        width: Math.min(implicitWidth, parent.width * 0.65)
                                        text: view.panelRoot ? view.panelRoot.accountText(providerSurface.modelData.account) : providerSurface.modelData.account
                                        visible: text !== ""
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        elide: Text.ElideMiddle
                                    }
                                }

                                Row {
                                    width: parent.width

                                    Text {
                                        width: parent.width - planLabel.width
                                        text: [providerSurface.modelData.refreshing ? "Refreshing…" : providerSurface.modelData.status, view.privateText(providerSurface.modelData.source)].filter(function (value) {
                                            return value !== "";
                                        }).join(" · ")
                                        color: providerSurface.modelData.errorKind !== "" || (!providerSurface.modelData.ready && !providerSurface.modelData.loading) ? Color.urgent : view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        id: planLabel
                                        text: providerSurface.modelData.plan
                                        visible: text !== ""
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                    }
                                }

                                Text {
                                    width: parent.width
                                    visible: view.relativeUpdated(providerSurface.modelData.updated) !== "" || providerSurface.modelData.stale
                                    text: providerSurface.modelData.stale ? [view.relativeUpdated(providerSurface.modelData.updated) !== "" ? "Last updated " + view.relativeUpdated(providerSurface.modelData.updated) : "Last update unavailable", view.relativeUpdated(providerSurface.modelData.staleSince) !== "" ? "stale since " + view.relativeUpdated(providerSurface.modelData.staleSince) : "stale"].join(" · ") : "Updated " + view.relativeUpdated(providerSurface.modelData.updated)
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                    elide: Text.ElideRight
                                }

                                Flow {
                                    width: parent.width
                                    spacing: Style.space(6)
                                    visible: view.setting("accountLayout", view.setting("codexAccountLayout", "Tabs")) === "Tabs" && providerSurface.modelData.provider === "codex" && view.panelRoot && view.panelRoot.service && view.panelRoot.service.codexAccountChoices().length > 1

                                    Repeater {
                                        model: view.panelRoot && view.panelRoot.service ? view.panelRoot.service.codexAccountChoices() : []

                                        delegate: Button {
                                            required property var modelData
                                            text: {
                                                var label = String(modelData.email || "");
                                                if (label === "")
                                                    label = modelData.ambient ? "Native" : String(modelData.id || "Account");
                                                return (modelData.active ? "● " : "") + label + " · " + modelData.resetLabel;
                                            }
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: view.panelRoot && view.panelRoot.service && !modelData.active && !view.panelRoot.service.providerConfigBusy
                                            onClicked: if (view.panelRoot && view.panelRoot.service)
                                                view.panelRoot.service.activateCodexAccount(modelData.id)
                                        }
                                    }
                                }

                                PanelSeparator {
                                    width: parent.width
                                    foreground: view.foreground
                                }

                                Column {
                                    width: parent.width
                                    visible: providerSurface.modelData.errorKind !== "" || providerSurface.modelData.stale
                                    spacing: Style.space(4)

                                    Text {
                                        width: parent.width
                                        text: view.privateText(view.noticeText(providerSurface.modelData))
                                        color: providerSurface.modelData.errorKind !== "" ? Color.urgent : view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                        maximumLineCount: view.isErrorExpanded(providerSurface.modelData.provider) ? 100 : 3
                                        elide: Text.ElideRight
                                    }

                                    Row {
                                        spacing: Style.space(7)

                                        Button {
                                            text: view.isErrorExpanded(providerSurface.modelData.provider) ? "Hide details" : "Show details"
                                            visible: view.noticeText(providerSurface.modelData).length > 160
                                            foreground: view.foreground
                                            focusable: true
                                            onClicked: view.toggleError(providerSurface.modelData.provider)
                                        }

                                        Button {
                                            text: "Copy error"
                                            visible: providerSurface.modelData.errorKind !== "" && view.noticeText(providerSurface.modelData) !== ""
                                            foreground: view.foreground
                                            focusable: true
                                            onClicked: view.copyText(view.noticeText(providerSurface.modelData))
                                        }
                                    }
                                }

                                Repeater {
                                    model: providerSurface.modelData.ready ? (providerSurface.modelData.windows || []) : []

                                    delegate: QuotaMetric {
                                        required property var modelData
                                        width: cardColumn.width
                                        metric: modelData
                                        panelRoot: view.panelRoot
                                        foreground: view.foreground
                                        muted: view.muted
                                        accent: providerSurface.providerAccent
                                        fontFamily: view.fontFamily()
                                        warningThreshold: Number(view.setting("warningThreshold", 90))
                                        showResetTimes: view.setting("showResetTimes", true) === true
                                        showPace: view.setting("paceVisible", true) === true
                                        showWarningMarkers: view.setting("quotaWarningMarkersVisible", true) === true
                                        showWorkdayTicks: view.setting("workdayTicksVisible", true) === true
                                    }
                                }

                                Text {
                                    width: parent.width
                                    visible: providerSurface.modelData.summary !== "" && (providerSurface.modelData.optionalSections || []).length === 0
                                    text: providerSurface.modelData.summary
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.bodySmall
                                    wrapMode: Text.WordWrap
                                }

                                Repeater {
                                    model: view.setting("showOptionalCreditsAndExtraUsage", true) === true ? (providerSurface.modelData.optionalSections || []) : []

                                    delegate: UsageExtraSection {
                                        required property var modelData
                                        width: cardColumn.width
                                        section: modelData
                                        panelRoot: view.panelRoot
                                        foreground: view.foreground
                                        muted: view.muted
                                        accent: providerSurface.providerAccent
                                        fontFamily: view.fontFamily()
                                        warningThreshold: Number(view.setting("warningThreshold", 90))
                                        showResetTimes: view.setting("showResetTimes", true) === true
                                        showWarningMarkers: view.setting("quotaWarningMarkersVisible", true) === true
                                    }
                                }

                                Column {
                                    width: parent.width
                                    spacing: Style.space(7)
                                    visible: (providerSurface.modelData.costStats || []).length > 0

                                    PanelSeparator {
                                        width: parent.width
                                        foreground: view.foreground
                                    }

                                    Grid {
                                        id: costGrid
                                        width: parent.width
                                        columns: 2
                                        columnSpacing: Style.space(12)
                                        rowSpacing: Style.space(7)

                                        Repeater {
                                            model: providerSurface.modelData.costStats || []

                                            delegate: Column {
                                                required property var modelData
                                                width: (costGrid.width - costGrid.columnSpacing) / 2
                                                spacing: Style.space(1)

                                                Text {
                                                    width: parent.width
                                                    text: modelData.label
                                                    color: view.muted
                                                    font.family: view.fontFamily()
                                                    font.pixelSize: Style.font.caption
                                                    elide: Text.ElideRight
                                                }

                                                Text {
                                                    width: parent.width
                                                    text: modelData.value
                                                    color: view.foreground
                                                    font.family: view.fontFamily()
                                                    font.pixelSize: Style.font.bodySmall
                                                    font.bold: true
                                                    elide: Text.ElideRight
                                                }
                                            }
                                        }
                                    }

                                    InlineChart {
                                        width: parent.width
                                        chart: providerSurface.modelData.costChart || null
                                        foreground: view.foreground
                                        muted: view.muted
                                        accent: providerSurface.providerAccent
                                    }

                                    Text {
                                        width: parent.width
                                        text: providerSurface.modelData.costCaption || ""
                                        visible: text !== ""
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                    }
                                }

                                Repeater {
                                    model: providerSurface.modelData.detailSections || []

                                    delegate: Column {
                                        id: compactSection
                                        required property var modelData
                                        width: cardColumn.width
                                        spacing: Style.space(4)

                                        Text {
                                            width: parent.width
                                            text: String(compactSection.modelData.title || "Details")
                                            color: view.muted
                                            font.family: view.fontFamily()
                                            font.pixelSize: Style.font.caption
                                            font.bold: true
                                        }

                                        InlineChart {
                                            width: parent.width
                                            chart: compactSection.modelData.chart || null
                                            sectionTitle: String(compactSection.modelData.title || "")
                                            foreground: view.foreground
                                            muted: view.muted
                                            accent: providerSurface.providerAccent
                                        }

                                        Repeater {
                                            model: Array.isArray(compactSection.modelData.rows) ? compactSection.modelData.rows : []

                                            delegate: Row {
                                                required property var modelData
                                                width: compactSection.width

                                                Text {
                                                    width: parent.width * 0.62
                                                    text: String(modelData.label || "")
                                                    color: view.muted
                                                    font.family: view.fontFamily()
                                                    font.pixelSize: Style.font.caption
                                                    elide: Text.ElideRight
                                                }
                                                Text {
                                                    width: parent.width * 0.38
                                                    text: view.panelRoot ? view.panelRoot.detailValue(modelData) : String(modelData.value || "")
                                                    horizontalAlignment: Text.AlignRight
                                                    color: view.foreground
                                                    font.family: view.fontFamily()
                                                    font.pixelSize: Style.font.caption
                                                    elide: Text.ElideLeft
                                                }
                                            }
                                        }
                                    }
                                }

                                Row {
                                    width: parent.width
                                    spacing: Style.space(8)
                                    visible: view.setting("showProviderDetails", false) === true || (view.setting("showDashboardActions", false) === true && view.panelRoot && view.panelRoot.service && view.panelRoot.service.hasDashboard(providerSurface.modelData.provider))

                                    Button {
                                        visible: view.setting("showProviderDetails", false) === true
                                        text: "Details"
                                        foreground: view.foreground
                                        focusable: true
                                        onClicked: if (view.panelRoot)
                                            view.panelRoot.openProviderSettings(providerSurface.modelData.provider)
                                    }

                                    Button {
                                        text: "Dashboard"
                                        visible: view.setting("showDashboardActions", false) === true && view.panelRoot && view.panelRoot.service && view.panelRoot.service.hasDashboard(providerSurface.modelData.provider)
                                        foreground: view.foreground
                                        focusable: true
                                        onClicked: if (view.panelRoot && view.panelRoot.service)
                                            view.panelRoot.service.openDashboard(providerSurface.modelData.provider)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Text {
                width: parent.width
                text: "ACTIONS"
                visible: view.setting("showActionSection", false) === true
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            Column {
                width: parent.width
                spacing: Style.space(2)
                visible: view.setting("showActionSection", false) === true

                Repeater {
                    model: [
                        {
                            key: "refresh",
                            icon: "󰑐",
                            title: "Refresh All",
                            subtitle: "Update every connected provider"
                        },
                        {
                            key: "settings",
                            icon: "󰒓",
                            title: "Settings",
                            subtitle: "Providers, display, warnings, advanced"
                        },
                        {
                            key: "about",
                            icon: "󰋼",
                            title: "About Omarchy AI Bar",
                            subtitle: "Version and platform information"
                        }
                    ]

                    delegate: BorderSurface {
                        id: actionRow
                        required property var modelData
                        width: usageColumn.width
                        height: Style.space(46)
                        color: actionMouse.containsMouse ? Style.hoverFillFor(view.foreground, Color.accent) : "transparent"
                        borderSpec: Border.none()
                        radius: Style.cornerRadius

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(10)
                            anchors.rightMargin: Style.space(10)
                            spacing: Style.space(10)

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                text: actionRow.modelData.icon
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.icon
                            }

                            Column {
                                width: parent.width - Style.space(42)
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.space(1)

                                Text {
                                    width: parent.width
                                    text: actionRow.modelData.title
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.bodySmall
                                }
                                Text {
                                    width: parent.width
                                    text: actionRow.modelData.subtitle
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                    elide: Text.ElideRight
                                }
                            }
                        }

                        MouseArea {
                            id: actionMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                if (!view.panelRoot)
                                    return;
                                if (actionRow.modelData.key === "refresh" && view.panelRoot.service)
                                    view.panelRoot.service.refreshAll();
                                else if (actionRow.modelData.key === "settings")
                                    view.panelRoot.openSettings();
                                else if (actionRow.modelData.key === "about")
                                    view.panelRoot.openSettingsPane("about");
                            }
                        }
                    }
                }
            }
        }
    }
}
