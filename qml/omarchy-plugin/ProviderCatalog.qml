import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Item {
    id: view

    property var panelRoot: null
    property alias scrollArea: catalogScroll

    readonly property color foreground: panelRoot ? panelRoot.foreground : Color.foreground
    readonly property color muted: panelRoot ? panelRoot.muted : Qt.darker(foreground, 1.55)
    readonly property var providers: {
        if (!panelRoot)
            return [];
        var query = panelRoot.providerQuery.trim().toLowerCase();
        return panelRoot.disabledRows.filter(function (row) {
            return query === "" || String(row.label).toLowerCase().indexOf(query) !== -1 || String(row.provider).toLowerCase().indexOf(query) !== -1;
        });
    }

    function fontFamily() {
        return panelRoot && panelRoot.bar ? panelRoot.bar.fontFamily : Style.font.family;
    }

    Column {
        anchors.fill: parent
        spacing: Style.space(8)

        TextField {
            id: providerSearch
            width: parent.width
            placeholderText: "Search available providers"
            text: view.panelRoot ? view.panelRoot.providerQuery : ""
            foreground: view.foreground
            onTextChanged: if (view.panelRoot)
                view.panelRoot.providerQuery = text
            Component.onCompleted: forceActiveFocus()
        }

        Row {
            width: parent.width

            Text {
                width: parent.width - resultCount.width
                text: "AVAILABLE PROVIDERS"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            Text {
                id: resultCount
                text: view.providers.length + " results"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
            }
        }

        Flickable {
            id: catalogScroll
            width: parent.width
            height: parent.height - providerSearch.height - Style.space(28)
            contentWidth: width
            contentHeight: providerList.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            interactive: contentHeight > height
            ScrollBar.vertical: ScrollBar {
                policy: ScrollBar.AsNeeded
            }

            Column {
                id: providerList
                width: catalogScroll.width
                spacing: Style.space(2)

                Repeater {
                    model: view.providers

                    delegate: BorderSurface {
                        id: catalogRow
                        required property var modelData
                        width: providerList.width
                        height: Style.space(50)
                        color: catalogMouse.containsMouse ? Style.hoverFillFor(view.foreground, Color.accent) : Style.normalFillFor(view.foreground, Color.accent)
                        borderSpec: Border.none()
                        radius: Style.cornerRadius

                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(12)
                            anchors.rightMargin: Style.space(10)
                            spacing: Style.space(8)

                            Column {
                                width: parent.width - enableButton.width - parent.spacing
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.space(1)

                                Text {
                                    width: parent.width
                                    text: catalogRow.modelData.label
                                    color: view.foreground
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.bodySmall
                                    elide: Text.ElideRight
                                }

                                Text {
                                    width: parent.width
                                    text: catalogRow.modelData.environmentKey !== "" ? catalogRow.modelData.environmentKey : (catalogRow.modelData.canLaunchLogin ? "Native login available" : (catalogRow.modelData.canStoreCredential ? "Secure credential" : "Automatic client or cloud configuration"))
                                    color: view.muted
                                    font.family: view.fontFamily()
                                    font.pixelSize: Style.font.caption
                                    elide: Text.ElideRight
                                }
                            }

                            Button {
                                id: enableButton
                                anchors.verticalCenter: parent.verticalCenter
                                text: catalogRow.modelData.eligibleToEnable ? "Enable" : "Configure"
                                foreground: view.foreground
                                focusable: true
                                enabled: !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                                onClicked: if (view.panelRoot && view.panelRoot.service) {
                                    var targetPanel = view.panelRoot;
                                    var targetProvider = catalogRow.modelData.provider;
                                    targetPanel.openProviderSettings(targetProvider);
                                    if (catalogRow.modelData.eligibleToEnable)
                                        targetPanel.service.setProviderEnabled(targetProvider, true);
                                }
                            }
                        }

                        MouseArea {
                            id: catalogMouse
                            anchors.fill: parent
                            anchors.rightMargin: enableButton.width + Style.space(16)
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: if (view.panelRoot)
                                view.panelRoot.openProviderSettings(catalogRow.modelData.provider)
                        }
                    }
                }
            }
        }
    }
}
