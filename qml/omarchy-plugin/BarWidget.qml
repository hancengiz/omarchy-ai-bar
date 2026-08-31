import QtQuick
import qs.Commons
import qs.Ui

BarWidget {
    id: root
    moduleName: "local.omarchy-ai-bar"

    readonly property var aiService: bar && bar.shell ? bar.shell.serviceFor("local.omarchy-ai-bar") : null
    readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
    readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false
    readonly property int serviceReadyGeneration: aiService ? aiService.readyGeneration : 0
    readonly property var selectedRow: selectBarRow()
    readonly property real selectedUsedPercent: selectedRow && selectedRow.ready ? Number(selectedRow.percent || 0) : 0
    readonly property real selectedDisplayPercent: setting("usageDirection", "Used") === "Remaining" ? 100 - selectedUsedPercent : selectedUsedPercent
    property bool openReported: false
    property var reportingService: null
    property var geometryService: null
    readonly property real openPanelIndicatorWidth: button.labelWidth
    readonly property real openPanelIndicatorHeight: Math.max(Style.space(10), Math.round(Style.bar.iconSlot * 0.55))
    readonly property string displayText: {
        if (!aiService)
            return vertical ? "AI" : "AI --";
        if (aiService.compatibilityFailure !== "")
            return vertical ? "!" : "AI !";
        var mode = String(setting("barDisplay", "AI and usage"));
        var percent = Math.round(selectedDisplayPercent) + "%";
        if (vertical || mode === "Icon only")
            return "AI";
        if (mode === "Usage only")
            return percent;
        if (mode === "Provider and usage")
            return (selectedRow ? selectedRow.label : "AI") + " " + percent;
        return "AI " + percent;
    }

    function selectBarRow() {
        var rows = aiService && Array.isArray(aiService.providerRows) ? aiService.providerRows : [];
        if (rows.length === 0)
            return null;
        var preferred = String(setting("preferredProvider", "Highest usage"));
        if (preferred !== "Highest usage") {
            for (var index = 0; index < rows.length; index++) {
                if (rows[index] && rows[index].label === preferred)
                    return rows[index];
            }
        }
        var selected = null;
        for (var rowIndex = 0; rowIndex < rows.length; rowIndex++) {
            var candidate = rows[rowIndex];
            if (!candidate || !candidate.ready)
                continue;
            if (!selected || Number(candidate.percent || 0) > Number(selected.percent || 0))
                selected = candidate;
        }
        return selected || rows[0];
    }

    function injectPanel() {
        var target = panelLoader.item;
        if (!target)
            return;
        if ("bar" in target)
            target.bar = root.bar;
        if ("settings" in target)
            target.settings = root.settings;
        if ("anchorItem" in target)
            target.anchorItem = button;
        if ("hostWidget" in target)
            target.hostWidget = root;
        if ("service" in target)
            target.service = root.aiService;
    }

    function registerGeometrySource() {
        if (geometryService === aiService)
            return;
        if (geometryService)
            geometryService.unregisterPanelGeometrySource(root);
        geometryService = aiService;
        if (geometryService)
            geometryService.registerPanelGeometrySource(root);
    }

    function debugPanelGeometry() {
        var target = panelLoader.item;
        return target && typeof target.debugGeometry === "function" ? target.debugGeometry() : null;
    }

    function open() {
        if (!panelLoader.item)
            return;
        if (aiService)
            aiService.claimPanel(root);
        if (!opened)
            panelLoader.item.open();
        reportOpenIfPossible();
    }

    function reportOpenIfPossible() {
        if (!opened || openReported || !aiService)
            return false;
        if (!aiService.reportPanelOpened())
            return false;
        openReported = true;
        reportingService = aiService;
        return true;
    }

    function finishClose(forSwitch) {
        if (panelLoader.item) {
            if (forSwitch && typeof panelLoader.item.closeForPopoutSwitch === "function")
                panelLoader.item.closeForPopoutSwitch();
            else
                panelLoader.item.close();
        }
        if (aiService)
            aiService.releasePanel(root);
        if (reportingService && reportingService !== aiService)
            reportingService.releasePanel(root);
        if (bar && bar.activePopout === root && typeof bar.releasePopout === "function")
            bar.releasePopout(root);
        if (openReported && reportingService)
            reportingService.reportPanelClosed();
        openReported = false;
        reportingService = null;
    }

    function close() {
        finishClose(false);
    }

    function togglePanel() {
        if (opened)
            close();
        else
            open();
    }

    function closeForPopoutSwitch() {
        finishClose(true);
    }

    function closeForServiceSwitch() {
        finishClose(true);
    }

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight

    onBarChanged: injectPanel()
    onSettingsChanged: injectPanel()
    onAiServiceChanged: {
        if (reportingService && reportingService !== aiService) {
            reportingService.releasePanel(root);
            if (openReported)
                reportingService.reportPanelClosed();
            openReported = false;
            reportingService = null;
        }
        registerGeometrySource();
        injectPanel();
        if (aiService && opened) {
            aiService.claimPanel(root);
            reportOpenIfPossible();
        }
    }
    onServiceReadyGenerationChanged: reportOpenIfPossible()
    Component.onCompleted: registerGeometrySource()
    Component.onDestruction: {
        if (geometryService)
            geometryService.unregisterPanelGeometrySource(root);
        geometryService = null;
        finishClose(false);
    }

    Loader {
        id: panelLoader
        active: true
        source: Qt.resolvedUrl("Panel.qml")
        visible: false
        onLoaded: {
            root.injectPanel();
            Qt.callLater(root.injectPanel);
        }
    }

    WidgetButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        text: root.displayText
        active: root.opened || (root.aiService && root.aiService.compatibilityFailure !== "") || root.selectedUsedPercent >= Number(root.setting("warningThreshold", 90))
        tooltipText: root.aiService ? "Omarchy AI Bar · " + root.aiService.connectionStatus + (root.selectedRow ? " · " + root.selectedRow.label : "") : "Omarchy AI Bar · Starting"

        onPressed: function (button) {
            if (button === Qt.RightButton || button === Qt.MiddleButton) {
                if (root.aiService)
                    root.aiService.refreshAll();
            } else {
                root.togglePanel();
            }
        }
    }
}
