import QtQuick
import qs.Commons

Item {
    id: root

    property var chart: null
    property string sectionTitle: ""
    property color foreground: Color.foreground
    property color muted: Qt.darker(foreground, 1.55)
    property color accent: Color.accent

    readonly property var points: chart ? (chart.points || []) : []
    visible: points.length > 0
    implicitHeight: visible ? chartColumn.implicitHeight : 0

    onChartChanged: plot.requestPaint()
    onWidthChanged: plot.requestPaint()
    onForegroundChanged: plot.requestPaint()
    onAccentChanged: plot.requestPaint()

    Column {
        id: chartColumn
        width: parent.width
        spacing: Style.space(5)

        Row {
            width: parent.width
            visible: titleText.text !== "" || unitText.text !== ""

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

            onPaint: {
                var context = getContext("2d");
                context.clearRect(0, 0, width, height);
                var values = root.points;
                if (values.length === 0)
                    return;
                var chartHeight = height - Style.space(22);
                var maximum = 0;
                for (var index = 0; index < values.length; index++)
                    maximum = Math.max(maximum, Number(values[index].value || 0));
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
                    for (var lineIndex = 0; lineIndex < values.length; lineIndex++) {
                        var x = step * lineIndex + step / 2;
                        var y = chartHeight - Math.max(0, Number(values[lineIndex].value || 0)) / maximum * (chartHeight - 4);
                        if (lineIndex === 0)
                            context.moveTo(x, y);
                        else
                            context.lineTo(x, y);
                    }
                    context.stroke();
                } else {
                    context.fillStyle = root.accent;
                    var barWidth = Math.max(2, Math.min(step * 0.68, Style.space(12)));
                    for (var barIndex = 0; barIndex < values.length; barIndex++) {
                        var barHeight = Math.max(1, Math.max(0, Number(values[barIndex].value || 0)) / maximum * (chartHeight - 4));
                        context.fillRect(step * barIndex + (step - barWidth) / 2, chartHeight - barHeight, barWidth, barHeight);
                    }
                }

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
    }
}
