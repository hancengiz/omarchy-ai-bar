import QtQuick
import qs.Commons
import qs.Ui

Item {
    id: root

    property var section: null
    property var panelRoot: null
    property color foreground: Color.foreground
    property color muted: Qt.darker(foreground, 1.55)
    property color accent: Color.accent
    property string fontFamily: Style.font.family
    property int warningThreshold: 90
    property bool showResetTimes: true
    property bool showWarningMarkers: true

    implicitHeight: sectionColumn.implicitHeight
    visible: section !== null

    function valueFor(row) {
        if (panelRoot && typeof panelRoot.detailValue === "function")
            return panelRoot.detailValue(row);
        return [row.value, row.secondary_value].filter(function (value) {
            return value !== null && value !== undefined && value !== "";
        }).join(" · ");
    }

    Column {
        id: sectionColumn
        width: parent.width
        spacing: Style.space(6)

        PanelSeparator {
            width: parent.width
            foreground: root.foreground
        }

        Text {
            width: parent.width
            text: root.section ? String(root.section.title || "Details") : "Details"
            color: root.muted
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
        }

        QuotaMetric {
            width: parent.width
            visible: root.section && root.section.metric !== null
            metric: root.section ? root.section.metric : null
            panelRoot: root.panelRoot
            foreground: root.foreground
            muted: root.muted
            accent: root.accent
            fontFamily: root.fontFamily
            warningThreshold: root.warningThreshold
            showResetTimes: root.showResetTimes
            showPace: false
            showWarningMarkers: root.showWarningMarkers
            showWorkdayTicks: false
        }

        Repeater {
            model: root.section ? (root.section.rows || []) : []

            delegate: Row {
                id: detailRow
                required property var modelData
                width: sectionColumn.width

                Text {
                    width: parent.width * 0.58
                    text: String(detailRow.modelData.label || "")
                    color: root.muted
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                }

                Text {
                    width: parent.width * 0.42
                    text: root.valueFor(detailRow.modelData)
                    horizontalAlignment: Text.AlignRight
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    elide: Text.ElideLeft
                }
            }
        }

        Text {
            width: parent.width
            visible: root.section && String(root.section.caption || "") !== ""
            text: root.section && root.section.captionSensitivity === "personal" && root.panelRoot ? root.panelRoot.detailValue({
                value: root.section.caption,
                secondary_value: null,
                sensitivity: "personal"
            }) : (root.section ? String(root.section.caption || "") : "")
            color: root.muted
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
        }
    }
}
