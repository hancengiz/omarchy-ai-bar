import QtQuick
import Quickshell.Io
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
    property var warnedProviders: ({})
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
        var rows = aiService && Array.isArray(aiService.configuredProviderRows) ? aiService.configuredProviderRows : [];
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

    function evaluateQuotaWarnings() {
        if (!aiService || !aiService.hasLiveSnapshot || setting("quotaWarningsEnabled", true) !== true)
            return;
        var rows = Array.isArray(aiService.configuredProviderRows) ? aiService.configuredProviderRows : [];
        var threshold = Number(setting("warningThreshold", 90));
        var next = {};
        for (var existing in warnedProviders)
            next[existing] = warnedProviders[existing];
        var pendingTitle = "";
        var pendingBody = "";
        for (var rowIndex = 0; rowIndex < rows.length; rowIndex++) {
            var row = rows[rowIndex];
            var highest = 0;
            var highestTitle = "quota";
            var windows = row && Array.isArray(row.windows) ? row.windows : [];
            for (var windowIndex = 0; windowIndex < windows.length; windowIndex++) {
                var window = windows[windowIndex];
                if (window && window.known && Number(window.percent || 0) >= highest) {
                    highest = Number(window.percent || 0);
                    highestTitle = String(window.title || "quota");
                }
            }
            if (highest < threshold) {
                delete next[row.provider];
                continue;
            }
            if (!next[row.provider] && pendingTitle === "") {
                pendingTitle = row.label + " quota warning";
                pendingBody = highestTitle + " is " + Math.round(highest) + "% used" + (row.reset !== "" ? " · resets " + row.reset : "");
            }
            next[row.provider] = true;
        }
        warnedProviders = next;
        if (pendingTitle !== "" && !warningProcess.running) {
            warningProcess.command = ["notify-send", "--app-name=Omarchy AI Bar", "--urgency=normal", pendingTitle, pendingBody];
            warningProcess.running = true;
        }
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
        // Every ordinary open starts on the CodexBar-style glanceable usage view.
        // Explicit provider/catalog/app-settings entry points call this first and
        // then apply their requested destination below.
        if (typeof panelLoader.item.showUsage === "function")
            panelLoader.item.showUsage();
        if (aiService)
            aiService.claimPanel(root);
        if (!opened)
            panelLoader.item.open();
        reportOpenIfPossible();
    }

    function openProviderSettings(provider) {
        open();
        if (panelLoader.item && typeof panelLoader.item.openProviderSettings === "function")
            panelLoader.item.openProviderSettings(provider);
    }

    function openProviderCatalog() {
        open();
        if (panelLoader.item && typeof panelLoader.item.openProviderCatalog === "function")
            panelLoader.item.openProviderCatalog();
    }

    function openAppSettings(pane) {
        open();
        if (panelLoader.item && typeof panelLoader.item.openSettingsPane === "function")
            panelLoader.item.openSettingsPane(pane);
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
    onSettingsChanged: {
        injectPanel();
        Qt.callLater(evaluateQuotaWarnings);
    }
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
        Qt.callLater(evaluateQuotaWarnings);
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

    Connections {
        target: root.aiService

        function onProviderRowsChanged() {
            root.evaluateQuotaWarnings();
        }
    }

    Process {
        id: warningProcess
        running: false
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
