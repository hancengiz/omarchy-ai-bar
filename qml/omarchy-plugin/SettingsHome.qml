import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Item {
    id: view

    property var panelRoot: null
    property alias scrollArea: settingsScroll

    readonly property color foreground: panelRoot ? panelRoot.foreground : Color.foreground
    readonly property color muted: panelRoot ? panelRoot.muted : Qt.darker(foreground, 1.55)
    readonly property var enabledRows: panelRoot ? panelRoot.enabledRows : []

    function fontFamily() {
        return panelRoot && panelRoot.bar ? panelRoot.bar.fontFamily : Style.font.family;
    }

    function moveProvider(index, offset) {
        var targetIndex = index + offset;
        if (!panelRoot || !panelRoot.service || index < 0 || targetIndex < 0 || index >= enabledRows.length || targetIndex >= enabledRows.length)
            return false;
        var providers = enabledRows.map(function (row) {
            return row.provider;
        });
        var moved = providers[index];
        providers[index] = providers[targetIndex];
        providers[targetIndex] = moved;
        return panelRoot.service.setProviderOrder(providers);
    }

    Flickable {
        id: settingsScroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: settingsColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
        }

        Column {
            id: settingsColumn
            width: settingsScroll.width
            spacing: Style.space(12)

            Text {
                width: parent.width
                text: "APP SETTINGS"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            Column {
                width: parent.width
                spacing: Style.space(2)

                Repeater {
                    model: [
                        {
                            key: "display",
                            icon: "󰍹",
                            title: "Display & Menu",
                            subtitle: "Quota cards, pace, markers, credits"
                        },
                        {
                            key: "notifications",
                            icon: "󰂚",
                            title: "Quota Warnings",
                            subtitle: "Warning threshold and visual alerts"
                        },
                        {
                            key: "advanced",
                            icon: "󰒓",
                            title: "Advanced",
                            subtitle: "Daemon, privacy, refresh, diagnostics"
                        },
                        {
                            key: "about",
                            icon: "󰋼",
                            title: "About",
                            subtitle: "Version, project, platform notes"
                        }
                    ]

                    delegate: BorderSurface {
                        id: appRow
                        required property var modelData
                        width: settingsColumn.width
                        height: Style.space(50)
                        color: appMouse.containsMouse ? Style.hoverFillFor(view.foreground, Color.accent) : Style.normalFillFor(view.foreground, Color.accent)
                        borderSpec: Border.none()
                        radius: Style.cornerRadius

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(12)
                            anchors.rightMargin: Style.space(12)
                            spacing: Style.space(10)

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                text: appRow.modelData.icon
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.icon
                            }

                            Column {
                                width: parent.width - Style.space(58)
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.space(1)

                                Text {
                                    width: parent.width
                                    text: appRow.modelData.title
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                    elide: Text.ElideRight
                                }

                                Text {
                                    width: parent.width
                                    text: appRow.modelData.subtitle
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                    elide: Text.ElideRight
                                }
                            }

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                text: "󰅂"
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.icon
                            }
                        }

                        MouseArea {
                            id: appMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: if (view.panelRoot)
                                view.panelRoot.openSettingsPane(appRow.modelData.key)
                        }
                    }
                }
            }

            Row {
                width: parent.width

                Text {
                    width: parent.width - providerCount.width
                    text: "PROVIDERS"
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    font.letterSpacing: 1
                }

                Text {
                    id: providerCount
                    text: view.enabledRows.length + " enabled"
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.caption
                }
            }

            Text {
                width: parent.width
                visible: view.enabledRows.length > 1
                text: "Use the arrows to set the provider order in the menu."
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
            }

            BorderSurface {
                width: parent.width
                implicitHeight: noProviders.implicitHeight + Style.space(24)
                visible: view.enabledRows.length === 0
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius

                Text {
                    id: noProviders
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    text: "No providers are enabled. Detected providers are enabled automatically; use Add Provider for a manual connection."
                    color: view.muted
                    font.family: view.fontFamily()
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.WordWrap
                }
            }

            Column {
                width: parent.width
                spacing: Style.space(2)

                Repeater {
                    model: view.enabledRows

                    delegate: BorderSurface {
                        id: providerRow
                        required property var modelData
                        required property int index
                        width: settingsColumn.width
                        height: Style.space(52)
                        color: providerMouse.containsMouse ? Style.hoverFillFor(view.foreground, Color.accent) : Style.normalFillFor(view.foreground, Color.accent)
                        borderSpec: Border.none()
                        radius: Style.cornerRadius

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(12)
                            anchors.rightMargin: Style.space(10)
                            spacing: Style.space(9)

                            Rectangle {
                                anchors.verticalCenter: parent.verticalCenter
                                width: Style.space(7)
                                height: width
                                radius: width / 2
                                color: providerRow.modelData.configured ? Color.accent : (providerRow.modelData.detected ? view.muted : Color.urgent)
                            }

                            Column {
                                width: parent.width - providerOrderControls.width - providerToggle.width - Style.space(47)
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.space(1)

                                Text {
                                    width: parent.width
                                    text: providerRow.modelData.label
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.body
                                    elide: Text.ElideRight
                                }

                                Text {
                                    width: parent.width
                                    text: providerRow.modelData.configured ? providerRow.modelData.status : (providerRow.modelData.detected ? "Detected · setup needed" : "Enabled manually · setup needed")
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                    elide: Text.ElideRight
                                }
                            }

                            Row {
                                id: providerOrderControls
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.space(2)

                                Button {
                                    width: Style.space(27)
                                    height: Style.space(30)
                                    text: "↑"
                                    tooltipText: "Move " + providerRow.modelData.label + " up"
                                    foreground: view.foreground
                                    horizontalPadding: 0
                                    verticalPadding: 0
                                    focusable: true
                                    enabled: providerRow.index > 0 && !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                                    opacity: enabled ? 1 : 0.35
                                    onClicked: view.moveProvider(providerRow.index, -1)
                                }

                                Button {
                                    width: Style.space(27)
                                    height: Style.space(30)
                                    text: "↓"
                                    tooltipText: "Move " + providerRow.modelData.label + " down"
                                    foreground: view.foreground
                                    horizontalPadding: 0
                                    verticalPadding: 0
                                    focusable: true
                                    enabled: providerRow.index + 1 < view.enabledRows.length && !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                                    opacity: enabled ? 1 : 0.35
                                    onClicked: view.moveProvider(providerRow.index, 1)
                                }
                            }

                            ToggleSwitch {
                                id: providerToggle
                                anchors.verticalCenter: parent.verticalCenter
                                checked: providerRow.modelData.enabled
                                busy: view.panelRoot && view.panelRoot.service ? view.panelRoot.service.providerConfigBusy : false
                                foreground: view.foreground
                                onToggled: if (view.panelRoot && view.panelRoot.service)
                                    view.panelRoot.service.setProviderEnabled(providerRow.modelData.provider, false)
                            }
                        }

                        MouseArea {
                            id: providerMouse
                            anchors.fill: parent
                            anchors.rightMargin: providerOrderControls.width + providerToggle.width + Style.space(29)
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: if (view.panelRoot)
                                view.panelRoot.openProviderSettings(providerRow.modelData.provider)
                        }
                    }
                }
            }

            BorderSurface {
                id: addProviderRow
                width: parent.width
                height: Style.space(46)
                color: addMouse.containsMouse ? Style.hoverFillFor(view.foreground, Color.accent) : Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.controlSpec("normal", view.foreground, Color.accent)
                radius: Style.cornerRadius

                Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(12)
                    anchors.rightMargin: Style.space(12)

                    Text {
                        width: parent.width - addChevron.width
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Add Provider"
                        color: view.foreground
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.body
                    }

                    Text {
                        id: addChevron
                        anchors.verticalCenter: parent.verticalCenter
                        text: "󰅂"
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.icon
                    }
                }

                MouseArea {
                    id: addMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: if (view.panelRoot)
                        view.panelRoot.openProviderCatalog()
                }
            }
        }
    }
}
