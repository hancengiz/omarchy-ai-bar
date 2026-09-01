import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Item {
    id: view

    property var panelRoot: null
    property alias scrollArea: paneScroll

    readonly property color foreground: panelRoot ? panelRoot.foreground : Color.foreground
    readonly property color muted: panelRoot ? panelRoot.muted : Qt.darker(foreground, 1.55)
    readonly property string pane: panelRoot ? panelRoot.settingsPane : ""

    function fontFamily() {
        return panelRoot && panelRoot.bar ? panelRoot.bar.fontFamily : Style.font.family;
    }

    function setting(key, fallback) {
        return panelRoot ? panelRoot.setting(key, fallback) : fallback;
    }

    function cycleBarDisplay() {
        var values = ["AI and usage", "Provider and usage", "Usage only", "Icon only"];
        var current = String(setting("barDisplay", values[0]));
        var index = values.indexOf(current);
        panelRoot.persistSetting("barDisplay", values[(index + 1) % values.length]);
    }

    Flickable {
        id: paneScroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: paneColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
        }

        Column {
            id: paneColumn
            width: paneScroll.width
            spacing: Style.space(12)

            Column {
                width: parent.width
                visible: view.pane === "display"
                spacing: Style.space(12)

                Text {
                    width: parent.width
                    text: "MENU BAR"
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    font.letterSpacing: 1
                }

                BorderSurface {
                    width: parent.width
                    implicitHeight: displayColumn.implicitHeight + Style.space(24)
                    color: Style.normalFillFor(view.foreground, Color.accent)
                    borderSpec: Border.none()
                    radius: Style.cornerRadius

                    Column {
                        id: displayColumn
                        anchors.centerIn: parent
                        width: parent.width - Style.space(24)
                        spacing: Style.space(12)

                        Row {
                            width: parent.width

                            Column {
                                width: parent.width - displayButton.width
                                spacing: Style.space(2)

                                Text {
                                    text: "Bar display"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    text: "What the bar shows when space permits"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                }
                            }

                            Button {
                                id: displayButton
                                text: String(view.setting("barDisplay", "AI and usage"))
                                foreground: view.foreground
                                focusable: true
                                onClicked: view.cycleBarDisplay()
                            }
                        }

                        PanelSeparator {
                            width: parent.width
                            foreground: view.foreground
                        }

                        Row {
                            width: parent.width

                            Column {
                                width: parent.width - panelHeightReset.width
                                spacing: Style.space(2)

                                Text {
                                    text: "Menu height"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    text: "Drag the handle at the bottom of the menu · " + Math.round(Number(view.setting("panelHeight", Style.space(680)))) + " px"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                }
                            }

                            Button {
                                id: panelHeightReset
                                text: "Reset"
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot)
                                    view.panelRoot.resetPanelHeight()
                            }
                        }

                        PanelSeparator {
                            width: parent.width
                            foreground: view.foreground
                        }

                        Row {
                            width: parent.width

                            Column {
                                width: parent.width - directionButton.width
                                spacing: Style.space(2)

                                Text {
                                    text: "Usage direction"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    text: "Show quota consumed or available"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                }
                            }

                            Button {
                                id: directionButton
                                text: String(view.setting("usageDirection", "Used"))
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot)
                                    view.panelRoot.persistSetting("usageDirection", text === "Used" ? "Remaining" : "Used")
                            }
                        }

                        PanelSeparator {
                            width: parent.width
                            foreground: view.foreground
                        }

                        Row {
                            width: parent.width

                            Column {
                                width: parent.width - resetSwitch.width
                                spacing: Style.space(2)

                                Text {
                                    text: "Show reset times"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    text: "Include each quota window's next reset"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                }
                            }

                            ToggleSwitch {
                                id: resetSwitch
                                anchors.verticalCenter: parent.verticalCenter
                                checked: view.setting("showResetTimes", true) === true
                                foreground: view.foreground
                                onToggled: if (view.panelRoot)
                                    view.panelRoot.persistSetting("showResetTimes", !checked)
                            }
                        }

                        Repeater {
                            model: [
                                {
                                    key: "paceVisible",
                                    title: "Pace forecasts",
                                    subtitle: "Show ideal pace, reserve, deficit, and run-out estimates",
                                    defaultValue: true
                                },
                                {
                                    key: "quotaWarningMarkersVisible",
                                    title: "Warning markers",
                                    subtitle: "Mark the warning threshold on quota bars",
                                    defaultValue: true
                                },
                                {
                                    key: "workdayTicksVisible",
                                    title: "Weekly workday ticks",
                                    subtitle: "Divide weekly bars into workday checkpoints",
                                    defaultValue: true
                                },
                                {
                                    key: "showOptionalCreditsAndExtraUsage",
                                    title: "Credits and extra usage",
                                    subtitle: "Show balances, budgets, and limit-reset credits",
                                    defaultValue: true
                                }
                            ]

                            delegate: Column {
                                id: displayOption
                                required property var modelData
                                width: displayColumn.width
                                spacing: Style.space(12)

                                PanelSeparator {
                                    width: parent.width
                                    foreground: view.foreground
                                }

                                Row {
                                    width: parent.width

                                    Column {
                                        width: parent.width - displayOptionSwitch.width
                                        spacing: Style.space(2)

                                        Text {
                                            text: displayOption.modelData.title
                                            color: view.foreground
                                            font.family: view.fontFamily()
                                            font.pixelSize: Style.font.body
                                        }
                                        Text {
                                            width: parent.width
                                            text: displayOption.modelData.subtitle
                                            color: view.muted
                                            font.family: view.fontFamily()
                                            font.pixelSize: Style.font.caption
                                            wrapMode: Text.WordWrap
                                        }
                                    }

                                    ToggleSwitch {
                                        id: displayOptionSwitch
                                        anchors.verticalCenter: parent.verticalCenter
                                        checked: view.setting(displayOption.modelData.key, displayOption.modelData.defaultValue) === true
                                        foreground: view.foreground
                                        onToggled: if (view.panelRoot)
                                            view.panelRoot.persistSetting(displayOption.modelData.key, !checked)
                                    }
                                }
                            }
                        }
                    }
                }

                Text {
                    width: parent.width
                    text: "ACTIVE PROVIDER"
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    font.letterSpacing: 1
                }

                BorderSurface {
                    width: parent.width
                    implicitHeight: preferredRow.implicitHeight + Style.space(22)
                    color: Style.normalFillFor(view.foreground, Color.accent)
                    borderSpec: Border.none()
                    radius: Style.cornerRadius

                    Row {
                        id: preferredRow
                        anchors.centerIn: parent
                        width: parent.width - Style.space(24)

                        Column {
                            width: parent.width - preferredButton.width
                            spacing: Style.space(2)

                            Text {
                                text: "Menu bar provider"
                                color: view.foreground
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.body
                            }
                            Text {
                                text: "Highest usage follows the most constrained account"
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                            }
                        }

                        Button {
                            id: preferredButton
                            text: String(view.setting("preferredProvider", "Highest usage"))
                            foreground: view.foreground
                            focusable: true
                            onClicked: if (view.panelRoot)
                                view.panelRoot.cyclePreferredProvider()
                        }
                    }
                }
            }

            Column {
                width: parent.width
                visible: view.pane === "notifications"
                spacing: Style.space(12)

                Text {
                    width: parent.width
                    text: "QUOTA WARNINGS"
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    font.letterSpacing: 1
                }

                BorderSurface {
                    width: parent.width
                    implicitHeight: warningColumn.implicitHeight + Style.space(24)
                    color: Style.normalFillFor(view.foreground, Color.accent)
                    borderSpec: Border.none()
                    radius: Style.cornerRadius

                    Column {
                        id: warningColumn
                        anchors.centerIn: parent
                        width: parent.width - Style.space(24)
                        spacing: Style.space(12)

                        Row {
                            width: parent.width

                            Column {
                                width: parent.width - warningsSwitch.width
                                spacing: Style.space(2)

                                Text {
                                    text: "Desktop warnings"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    text: "Notify once when a provider crosses the threshold"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                }
                            }

                            ToggleSwitch {
                                id: warningsSwitch
                                anchors.verticalCenter: parent.verticalCenter
                                checked: view.setting("quotaWarningsEnabled", true) === true
                                foreground: view.foreground
                                onToggled: if (view.panelRoot)
                                    view.panelRoot.persistSetting("quotaWarningsEnabled", !checked)
                            }
                        }

                        PanelSeparator {
                            width: parent.width
                            foreground: view.foreground
                        }

                        Row {
                            width: parent.width
                            spacing: Style.space(8)

                            Column {
                                width: parent.width - minusButton.width - plusButton.width - thresholdText.width - parent.spacing * 3
                                spacing: Style.space(2)

                                Text {
                                    text: "Warn at"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    text: "Percent used across any known quota window"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                }
                            }

                            Button {
                                id: minusButton
                                text: "−"
                                foreground: view.foreground
                                focusable: true
                                enabled: Number(view.setting("warningThreshold", 90)) > 50
                                onClicked: if (view.panelRoot)
                                    view.panelRoot.persistSetting("warningThreshold", Math.max(50, Number(view.setting("warningThreshold", 90)) - 5))
                            }

                            Text {
                                id: thresholdText
                                anchors.verticalCenter: parent.verticalCenter
                                text: Number(view.setting("warningThreshold", 90)) + "%"
                                color: view.foreground
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.body
                                font.bold: true
                            }

                            Button {
                                id: plusButton
                                text: "+"
                                foreground: view.foreground
                                focusable: true
                                enabled: Number(view.setting("warningThreshold", 90)) < 100
                                onClicked: if (view.panelRoot)
                                    view.panelRoot.persistSetting("warningThreshold", Math.min(100, Number(view.setting("warningThreshold", 90)) + 5))
                            }
                        }
                    }
                }

                Text {
                    width: parent.width
                    text: "The bar and usage meters turn urgent at this level. Linux desktop notifications use Omarchy's notification daemon and are re-armed after usage falls below the threshold."
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.WordWrap
                }
            }

            Column {
                width: parent.width
                visible: view.pane === "advanced"
                spacing: Style.space(12)

                Text {
                    width: parent.width
                    text: "SERVICE"
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    font.letterSpacing: 1
                }

                BorderSurface {
                    width: parent.width
                    implicitHeight: advancedColumn.implicitHeight + Style.space(24)
                    color: Style.normalFillFor(view.foreground, Color.accent)
                    borderSpec: Border.none()
                    radius: Style.cornerRadius

                    Column {
                        id: advancedColumn
                        anchors.centerIn: parent
                        width: parent.width - Style.space(24)
                        spacing: Style.space(9)

                        Text {
                            width: parent.width
                            text: "Connection"
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.caption
                        }
                        Text {
                            width: parent.width
                            text: view.panelRoot && view.panelRoot.service ? view.panelRoot.service.connectionStatus : "Starting"
                            color: view.foreground
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.body
                            font.bold: true
                        }
                        Text {
                            width: parent.width
                            text: view.panelRoot && view.panelRoot.service ? (view.panelRoot.service.transportConnected ? "Bridge connected" : "Bridge disconnected") : "Service unavailable"
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.bodySmall
                        }

                        PanelSeparator {
                            width: parent.width
                            foreground: view.foreground
                        }

                        Text {
                            width: parent.width
                            text: "Providers"
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.caption
                        }
                        Text {
                            width: parent.width
                            text: (view.panelRoot ? view.panelRoot.configuredRows.length : 0) + " connected · " + (view.panelRoot ? view.panelRoot.enabledRows.length : 0) + " enabled"
                            color: view.foreground
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.body
                        }

                        Row {
                            spacing: Style.space(8)

                            Button {
                                text: "Refresh now"
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot && view.panelRoot.service)
                                    view.panelRoot.service.refreshAll()
                            }

                            Button {
                                text: "Restart service"
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot && view.panelRoot.service)
                                    view.panelRoot.service.restartDaemonAfterConfiguration()
                            }
                        }

                        PanelSeparator {
                            width: parent.width
                            foreground: view.foreground
                        }

                        Row {
                            width: parent.width

                            Column {
                                width: parent.width - privacySwitch.width
                                spacing: Style.space(2)

                                Text {
                                    text: "Hide personal information"
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                }
                                Text {
                                    width: parent.width
                                    text: "Redact accounts and personal provider details in the menu"
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                    wrapMode: Text.WordWrap
                                }
                            }

                            ToggleSwitch {
                                id: privacySwitch
                                anchors.verticalCenter: parent.verticalCenter
                                checked: view.setting("hidePersonalInfo", false) === true
                                foreground: view.foreground
                                onToggled: if (view.panelRoot)
                                    view.panelRoot.persistSetting("hidePersonalInfo", !checked)
                            }
                        }
                    }
                }

                Text {
                    width: parent.width
                    text: "Credentials are read from provider clients, environment variables, cloud configuration, or freedesktop Secret Service. Secrets are never displayed here."
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.WordWrap
                }
            }

            Column {
                width: parent.width
                visible: view.pane === "about"
                spacing: Style.space(12)

                BorderSurface {
                    width: parent.width
                    implicitHeight: aboutColumn.implicitHeight + Style.space(28)
                    color: Style.normalFillFor(view.foreground, Color.accent)
                    borderSpec: Border.controlSpec("normal", view.foreground, Color.accent)
                    radius: Style.cornerRadius

                    Column {
                        id: aboutColumn
                        anchors.centerIn: parent
                        width: parent.width - Style.space(28)
                        spacing: Style.space(7)

                        Text {
                            width: parent.width
                            text: "Omarchy AI Bar"
                            color: view.foreground
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.subtitle
                            font.bold: true
                        }
                        Text {
                            width: parent.width
                            text: "Version 0.4.0"
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.bodySmall
                        }
                        Text {
                            width: parent.width
                            text: "A native Rust usage daemon and Omarchy shell interface for provider quotas, resets, credits, costs, and status."
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.bodySmall
                            wrapMode: Text.WordWrap
                        }
                        Text {
                            width: parent.width
                            text: "Ported from CodexBar and customized for Omarchy by Cengiz Han (cengizhan.bio)."
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.bodySmall
                            wrapMode: Text.WordWrap
                        }
                        Text {
                            width: parent.width
                            text: "github.com/hancengiz/omarchy-ai-bar"
                            color: Color.accent
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.bodySmall
                            wrapMode: Text.WrapAnywhere
                        }
                        Row {
                            spacing: Style.space(8)

                            Button {
                                text: "Source code"
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot && view.panelRoot.service)
                                    view.panelRoot.service.openProjectLink("source")
                            }

                            Button {
                                text: "Cengiz Han"
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot && view.panelRoot.service)
                                    view.panelRoot.service.openProjectLink("author")
                            }

                            Button {
                                text: "CodexBar"
                                foreground: view.foreground
                                focusable: true
                                onClicked: if (view.panelRoot && view.panelRoot.service)
                                    view.panelRoot.service.openProjectLink("codexbar")
                            }
                        }
                    }
                }

                Text {
                    width: parent.width
                    text: "Linux equivalents are used for secure credentials, login terminals, notifications, and startup. Apple-only Keychain, Sparkle, Dock, and macOS menu-bar APIs do not apply. AUR/pacman updates are planned but not published yet; use a source build or direct release until then."
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
