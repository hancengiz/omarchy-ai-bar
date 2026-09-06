import QtQuick
import qs.Commons

Item {
    id: root

    property var chart: null
    property string sectionTitle: ""
    property bool compact: false
    property int selectedIndex: -1
    activeFocusOnTab: visible
    Accessible.role: Accessible.Graphic
    Accessible.name: chart ? String(chart.title || "History") : "History"
    Accessible.description: detailText.text

    function known(point) {
        return point && point.value !== null && point.value !== undefined && isFinite(Number(point.value));
    }

    function select(index) {
        selectedIndex = Math.max(0, Math.min(points.length - 1, index));
        plot.requestPaint();
    }

    Keys.onLeftPressed: select((selectedIndex < 0 ? points.length - 1 : selectedIndex) - 1)
    Keys.onRightPressed: select((selectedIndex < 0 ? -1 : selectedIndex) + 1)
    Keys.onPressed: event => {
        if (event.key === Qt.Key_Home) {
            select(0);
            event.accepted = true;
        } else if (event.key === Qt.Key_End) {
            select(points.length - 1);
            event.accepted = true;
        }
    }
    property color foreground: Color.foreground
    property color muted: Qt.darker(foreground, 1.55)
    property color accent: Color.accent

    readonly property var points: chart ? (chart.points || []) : []
    visible: points.length > 0
    implicitHeight: points.length > 0 ? chartColumn.implicitHeight : 0

    onChartChanged: {
        selectedIndex = -1;
        plot.requestPaint();
    }
    onWidthChanged: plot.requestPaint()
    onForegroundChanged: plot.requestPaint()
    onAccentChanged: plot.requestPaint()

    Column {
        id: chartColumn
        width: parent.width
        spacing: Style.space(5)

        Row {
            width: parent.width
            visible: !root.compact && (titleText.text !== "" || unitText.text !== "")

            Text {
                id: titleText
                width: parent.width - unitText.width
                text: root.chart && String(root.chart.title || "").trim().toLowerCase() !== root.sectionTitle.trim().toLowerCase() ? String(root.chart.title || "") : ""
                color: root.foreground
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideRight
            }

            Text {
                id: unitText
                text: root.chart ? String(root.chart.unit || "") : ""
                color: root.muted
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
            }
        }

        Canvas {
            id: plot
            width: parent.width
            height: Style.space(104)

            MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                onPositionChanged: mouse => root.select(Math.floor(mouse.x / width * root.points.length))
                onClicked: root.forceActiveFocus()
            }

            onPaint: {
                var context = getContext("2d");
                context.clearRect(0, 0, width, height);
                var values = root.points;
                if (values.length === 0)
                    return;
                var chartHeight = height - Style.space(22);
                var maximum = 0;
                for (var index = 0; index < values.length; index++)
                    if (root.known(values[index]))
                        maximum = Math.max(maximum, Number(values[index].value));
                maximum = Math.max(1, maximum);
                var step = width / Math.max(1, values.length);
                context.strokeStyle = root.muted;
                context.globalAlpha = 0.28;
                context.lineWidth = 1;
                context.beginPath();
                context.moveTo(0, chartHeight + 0.5);
                context.lineTo(width, chartHeight + 0.5);
                context.stroke();
                context.globalAlpha = 1;

                if (root.chart && root.chart.kind === "line") {
                    context.strokeStyle = root.accent;
                    context.lineWidth = 2;
                    context.beginPath();
                    var connected = false;
                    for (var lineIndex = 0; lineIndex < values.length; lineIndex++) {
                        if (!root.known(values[lineIndex])) {
                            connected = false;
                            continue;
                        }
                        var x = step * lineIndex + step / 2;
                        var y = chartHeight - Math.max(0, Number(values[lineIndex].value || 0)) / maximum * (chartHeight - 4);
                        if (!connected)
                            context.moveTo(x, y);
                        else
                            context.lineTo(x, y);
                        connected = true;
                    }
                    context.stroke();
                } else {
                    context.fillStyle = root.accent;
                    var barWidth = Math.max(2, Math.min(step * 0.68, Style.space(12)));
                    for (var barIndex = 0; barIndex < values.length; barIndex++) {
                        if (!root.known(values[barIndex])) {
                            context.fillStyle = root.muted;
                            context.globalAlpha = 0.35;
                            context.fillRect(step * barIndex + (step - barWidth) / 2, chartHeight - 4, barWidth, 2);
                            context.globalAlpha = 1;
                            continue;
                        }
                        context.fillStyle = root.accent;
                        context.globalAlpha = root.selectedIndex < 0 || root.selectedIndex === barIndex ? 1 : 0.5;
                        var barHeight = Math.max(1, Math.max(0, Number(values[barIndex].value || 0)) / maximum * (chartHeight - 4));
                        context.fillRect(step * barIndex + (step - barWidth) / 2, chartHeight - barHeight, barWidth, barHeight);
                    }
                }

                context.globalAlpha = 1;
                context.fillStyle = root.muted;
                context.font = Style.font.caption + "px " + Style.font.family;
                context.textBaseline = "bottom";
                var first = String(values[0].label || "");
                var last = String(values[values.length - 1].label || "");
                context.textAlign = "left";
                context.fillText(first, 0, height);
                if (values.length > 1) {
                    context.textAlign = "right";
                    context.fillText(last, width, height);
                }
            }
        }
        Text {
            width: parent.width
            visible: !root.compact && root.points.some(function (point) {
                return !root.known(point);
            })
            text: "Dashes indicate unavailable values"
            color: root.muted
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
        }

        Text {
            id: detailText
            visible: !root.compact || root.selectedIndex >= 0 || root.activeFocus
            width: parent.width
            text: {
                if (root.points.length === 0)
                    return "";
                var point = root.points[root.selectedIndex < 0 ? root.points.length - 1 : root.selectedIndex];
                var exact = point.exact !== undefined ? point.exact : String(point.value);
                var unit = String(root.chart.unit || "");
                var value = root.known(point) ? (unit === "$" ? "$" + exact : exact + " " + unit) : (point.note || "Unknown");
                return String(point.date || point.label || "") + " · " + value;
            }
            color: root.activeFocus ? root.accent : root.muted
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
        }
    }
}
