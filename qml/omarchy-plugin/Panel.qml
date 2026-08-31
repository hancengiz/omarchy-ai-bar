import QtQuick
import qs.Commons
import qs.Ui

Panel {
    id: root
    moduleName: "local.omarchy-ai-bar"
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null
    property var service: null

    readonly property var barIdentity: hostWidget || root
    readonly property real usagePercent: service ? service.usedPercent : 0
    readonly property string providerName: service ? service.providerLabel : "AI"
    readonly property string statusText: service ? service.connectionStatus : "Starting"
    readonly property var visibleProviderRows: {
        var rows = service && Array.isArray(service.providerRows) ? service.providerRows : [];
        if (setting("showUnavailable", true) === true)
            return rows;
        return rows.filter(function (row) {
            return row && row.ready;
        });
    }
    readonly property string resetText: {
        var sample = service ? service.displaySample : null;
        var primary = sample && sample.primary ? sample.primary : null;
        return primary && primary.reset_description ? String(primary.reset_description) : "Reset unavailable";
    }

    function displayPercent(row) {
        var used = Math.max(0, Math.min(100, Number(row && row.percent || 0)));
        return setting("usageDirection", "Used") === "Remaining" ? 100 - used : used;
    }

    function usageLabel(row) {
        var direction = setting("usageDirection", "Used") === "Remaining" ? "remaining" : "used";
        return Math.round(displayPercent(row)) + "% " + direction;
    }

    function debugGeometry() {
        return {
            monitor: popup.screen ? String(popup.screen.name || "") : "",
            open: root.opened === true,
            ownsPopout: Boolean(root.bar && root.hostWidget && root.bar.activePopout === root.hostWidget),
            foreignPopoutActive: Boolean(root.bar && root.bar.activePopout !== null && root.bar.activePopout !== root.hostWidget),
            barPosition: String(popup.barPos || ""),
            anchorX: Number(popup.anchorScreenPos.x),
            anchorY: Number(popup.anchorScreenPos.y),
            anchorWidth: Number(popup.anchorW),
            anchorHeight: Number(popup.anchorH),
            cardX: Number(popup.cardOrigin.x),
            cardY: Number(popup.cardOrigin.y),
            cardWidth: Number(popup.contentWidth),
            cardHeight: Number(popup.contentHeight),
            screenWidth: Number(popup.screenW),
            screenHeight: Number(popup.screenH),
            barWidth: Number(popup.barW),
            barHeight: Number(popup.barH),
            gap: Number(popup.gap),
            margin: Number(popup.margin)
        };
    }

    function switchPanel(direction) {
        if (bar && typeof bar.switchPanelFrom === "function")
            return bar.switchPanelFrom(barIdentity, direction);
        return false;
    }

    function requestClose() {
        if (hostWidget && typeof hostWidget.close === "function")
            hostWidget.close();
        else {
            root.close();
            if (service)
                service.releasePanel(root.barIdentity);
            if (bar && bar.activePopout === root.barIdentity && typeof bar.releasePopout === "function")
                bar.releasePopout(root.barIdentity);
        }
    }

    KeyboardPanel {
        id: popup
        anchorItem: root.anchorItem
        owner: root.barIdentity
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: popup.fittedContentWidth(Style.space(390))
        contentHeight: popup.fittedContentHeight(content.implicitHeight)

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            onCloseRequested: root.requestClose()
            onTabRequested: function (direction) {
                root.switchPanel(direction);
            }
            onTextKey: function (text) {
                if ((text === "r" || text === "R") && root.service)
                    root.service.refreshAll();
            }

            Column {
                id: content
                width: parent.width
                spacing: Style.space(12)

                Row {
                    width: parent.width
                    spacing: Style.space(10)

                    Column {
                        width: parent.width - statusBadge.width - parent.spacing
                        spacing: Style.space(2)

                        Text {
                            width: parent.width
                            text: "Omarchy AI Bar"
                            color: root.bar ? root.bar.foreground : Color.foreground
                            font.family: root.bar ? root.bar.fontFamily : Style.font.family
                            font.pixelSize: Style.font.subtitle
                            font.bold: true
                            elide: Text.ElideRight
                        }

                        Text {
                            width: parent.width
                            text: root.visibleProviderRows.length + " providers · " + String(root.setting("usageDirection", "Used")).toLowerCase() + " quota"
                            color: Color.muted
                            font.family: root.bar ? root.bar.fontFamily : Style.font.family
                            font.pixelSize: Style.font.bodySmall
                            elide: Text.ElideRight
                        }
                    }

                    Text {
                        id: statusBadge
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.statusText
                        color: root.service && root.service.compatibilityFailure !== "" ? Color.urgent : (root.bar ? root.bar.foreground : Color.foreground)
                        font.family: root.bar ? root.bar.fontFamily : Style.font.family
                        font.pixelSize: Style.font.caption
                    }
                }

                PanelSeparator {
                    width: parent.width
                    foreground: root.bar ? root.bar.foreground : Color.foreground
                }

                Column {
                    width: parent.width
                    spacing: Style.space(10)

                    Repeater {
                        model: root.visibleProviderRows

                        delegate: Column {
                            required property var modelData
                            width: parent.width
                            spacing: Style.space(5)

                            Row {
                                width: parent.width

                                Text {
                                    width: parent.width - providerUsage.width
                                    text: modelData.label
                                    color: root.bar ? root.bar.foreground : Color.foreground
                                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                                    font.pixelSize: Style.font.body
                                    font.bold: true
                                    elide: Text.ElideRight
                                }

                                Text {
                                    id: providerUsage
                                    text: modelData.ready ? root.usageLabel(modelData) : modelData.status
                                    color: modelData.ready ? (root.bar ? root.bar.foreground : Color.foreground) : Color.muted
                                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                                    font.pixelSize: Style.font.bodySmall
                                }
                            }

                            Rectangle {
                                width: parent.width
                                height: Style.space(7)
                                radius: height / 2
                                color: Style.normalFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)

                                Rectangle {
                                    width: parent.width * root.displayPercent(modelData) / 100
                                    height: parent.height
                                    radius: parent.radius
                                    color: Number(modelData.percent || 0) >= Number(root.setting("warningThreshold", 90)) ? Color.urgent : Color.accent
                                }
                            }

                            Text {
                                width: parent.width
                                visible: root.setting("showResetTimes", true) === true && modelData.reset !== ""
                                text: modelData.reset
                                color: Color.muted
                                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                                font.pixelSize: Style.font.caption
                                elide: Text.ElideRight
                            }
                        }
                    }
                }

                Text {
                    width: parent.width
                    visible: root.service && root.service.compatibilityFailure !== ""
                    text: "Bridge compatibility: " + root.service.compatibilityFailure
                    color: Color.urgent
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.Wrap
                }

                Row {
                    anchors.right: parent.right
                    spacing: Style.space(6)

                    Button {
                        text: "Refresh"
                        iconText: "󰑐"
                        foreground: root.bar ? root.bar.foreground : Color.foreground
                        focusable: true
                        onClicked: if (root.service)
                            root.service.refreshAll()
                    }

                    Button {
                        text: "Close"
                        foreground: root.bar ? root.bar.foreground : Color.foreground
                        focusable: true
                        onClicked: root.requestClose()
                    }
                }
            }
        }
    }
}
