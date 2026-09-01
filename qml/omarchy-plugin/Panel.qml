import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Panel {
    id: root
    moduleName: "local.omarchy-ai-bar"
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null
    property var service: null
    property bool settingsOpen: false
    property string selectedProvider: ""
    property string settingsPane: ""
    property string providerQuery: ""
    property bool catalogOpen: false
    property real localPanelHeight: -1
    property bool resizingPanel: false

    readonly property var barIdentity: hostWidget || root
    readonly property color foreground: root.bar ? root.bar.foreground : Color.foreground
    readonly property color muted: Qt.darker(foreground, 1.55)
    readonly property var configuredRows: service && Array.isArray(service.configuredProviderRows) ? service.configuredProviderRows : []
    readonly property var allRows: service && Array.isArray(service.providerRows) ? service.providerRows : []
    readonly property var enabledRows: allRows.filter(function (row) {
        return row && row.enabled;
    })
    readonly property var disabledRows: allRows.filter(function (row) {
        return row && !row.enabled;
    })
    readonly property var filteredRows: allRows.filter(function (row) {
        var query = root.providerQuery.trim().toLowerCase();
        return query === "" || String(row.label).toLowerCase().indexOf(query) !== -1 || String(row.provider).toLowerCase().indexOf(query) !== -1;
    })
    readonly property var selectedRow: {
        for (var index = 0; index < allRows.length; index++) {
            if (allRows[index] && allRows[index].provider === selectedProvider)
                return allRows[index];
        }
        return null;
    }

    function displayPercent(value) {
        var used = Math.max(0, Math.min(100, Number(value || 0)));
        return setting("usageDirection", "Used") === "Remaining" ? 100 - used : used;
    }

    function percentageLabel(value) {
        var direction = setting("usageDirection", "Used") === "Remaining" ? "remaining" : "used";
        return Math.round(displayPercent(value)) + "% " + direction;
    }

    function accountText(value) {
        var raw = String(value || "");
        if (raw === "" || setting("hidePersonalInfo", false) !== true)
            return raw;
        var at = raw.indexOf("@");
        return at > 0 ? raw.slice(0, 1) + "•••" + raw.slice(at) : "Hidden";
    }

    function privacyText(value) {
        var raw = String(value || "");
        if (raw === "" || setting("hidePersonalInfo", false) !== true)
            return raw;
        return raw.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, function (email) {
            var at = email.indexOf("@");
            return at > 0 ? email.slice(0, 1) + "•••" + email.slice(at) : "Hidden";
        });
    }

    function detailValue(row) {
        if (!row)
            return "";
        if (setting("hidePersonalInfo", false) === true && String(row.sensitivity || "") === "personal")
            return "Hidden";
        return privacyText([row.value, row.secondary_value].filter(function (value) {
            return value !== null && value !== undefined && value !== "";
        }).join(" · "));
    }

    function openSettings() {
        settingsOpen = true;
        selectedProvider = "";
        settingsPane = "";
        providerQuery = "";
        catalogOpen = false;
    }

    function showUsage() {
        settingsOpen = false;
        selectedProvider = "";
        settingsPane = "";
        providerQuery = "";
        catalogOpen = false;
        Qt.callLater(resetCurrentScroll);
    }

    function openProviderSettings(provider) {
        settingsOpen = true;
        selectedProvider = String(provider || "");
        settingsPane = "";
        providerQuery = "";
    }

    function openProviderCatalog() {
        openSettings();
        catalogOpen = true;
    }

    function openSettingsPane(pane) {
        settingsOpen = true;
        selectedProvider = "";
        settingsPane = String(pane || "");
    }

    function paneTitle() {
        var titles = {
            general: "General",
            display: "Display & Menu",
            usage: "Usage & Spend",
            notifications: "Quota Warnings",
            menu: "Menu",
            privacy: "Privacy",
            hooks: "Hooks",
            plugins: "Plugins",
            advanced: "Advanced",
            about: "About"
        };
        return catalogOpen ? "Add Provider" : (titles[settingsPane] || "Providers");
    }

    function persistSetting(key, value) {
        if (!root.bar || !root.bar.shell || typeof root.bar.shell.updateEntryInline !== "function")
            return false;
        var entry = {
            id: root.moduleName
        };
        var currentSettings = root.settings || {};
        for (var existingKey in currentSettings) {
            if (existingKey !== "id")
                entry[existingKey] = currentSettings[existingKey];
        }
        entry[key] = value;
        root.bar.shell.updateEntryInline(root.moduleName, entry);
        return true;
    }

    function defaultPanelHeight() {
        return Style.space(680);
    }

    function clampedPanelHeight(value) {
        var maximum = popup.availableCardHeight > 0 ? popup.availableCardHeight : defaultPanelHeight();
        var minimum = Math.min(maximum, Style.space(420));
        return Math.round(Math.max(minimum, Math.min(maximum, Number(value) || defaultPanelHeight())));
    }

    function currentPanelHeight() {
        var configured = Number(setting("panelHeight", defaultPanelHeight()));
        return clampedPanelHeight(localPanelHeight >= 0 ? localPanelHeight : configured);
    }

    function resetPanelHeight() {
        localPanelHeight = clampedPanelHeight(defaultPanelHeight());
        persistSetting("panelHeight", Math.round(localPanelHeight));
    }

    function finishPanelResize() {
        if (!resizingPanel)
            return;
        resizingPanel = false;
        localPanelHeight = clampedPanelHeight(localPanelHeight);
        persistSetting("panelHeight", Math.round(localPanelHeight));
    }

    function cyclePreferredProvider() {
        var values = ["Highest usage"];
        for (var index = 0; index < configuredRows.length; index++) {
            var row = configuredRows[index];
            if (row && values.indexOf(row.label) === -1)
                values.push(row.label);
        }
        var current = String(setting("preferredProvider", "Highest usage"));
        var currentIndex = values.indexOf(current);
        persistSetting("preferredProvider", values[(currentIndex + 1) % values.length]);
    }

    function resetCurrentScroll() {
        if (viewLoader.item && viewLoader.item.scrollArea)
            viewLoader.item.scrollArea.contentY = 0;
    }

    function navigateBack() {
        if (selectedProvider !== "") {
            selectedProvider = "";
            return true;
        }
        if (settingsPane !== "") {
            settingsPane = "";
            return true;
        }
        if (catalogOpen) {
            catalogOpen = false;
            providerQuery = "";
            return true;
        }
        if (settingsOpen) {
            settingsOpen = false;
            return true;
        }
        return false;
    }

    function debugGeometry() {
        return {
            monitor: popup.screen ? String(popup.screen.name || "") : "",
            open: root.opened === true,
            view: root.settingsOpen ? (root.selectedProvider !== "" ? "provider-detail" : (root.settingsPane !== "" ? root.settingsPane : (root.catalogOpen ? "provider-catalog" : "settings"))) : "usage",
            visibleProviders: root.configuredRows.length,
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
            configuredCardHeight: Number(root.setting("panelHeight", root.defaultPanelHeight())),
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

    onOpenedChanged: if (opened)
        Qt.callLater(resetCurrentScroll)

    KeyboardPanel {
        id: popup
        anchorItem: root.anchorItem
        owner: root.barIdentity
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: popup.fittedContentWidth(Style.space(420))
        contentHeight: root.currentPanelHeight()

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            onCloseRequested: {
                if (!root.navigateBack())
                    root.requestClose();
            }
            onTabRequested: function (direction) {
                root.switchPanel(direction);
            }
            onMoveRequested: function (dx, dy) {
                if (dy === 0 || !viewLoader.item || !viewLoader.item.scrollArea)
                    return;
                var scroll = viewLoader.item.scrollArea;
                scroll.contentY = Math.max(0, Math.min(scroll.contentHeight - scroll.height, scroll.contentY + dy * Style.space(56)));
            }
            onTextKey: function (text) {
                if ((text === "r" || text === "R") && root.service && !root.settingsOpen)
                    root.service.refreshAll();
            }

            Column {
                id: panelContent
                width: parent.width
                height: parent.height
                spacing: Style.space(10)

                Row {
                    id: headerRow
                    width: parent.width
                    spacing: Style.space(8)

                    PanelActionButton {
                        id: backButton
                        visible: root.settingsOpen
                        iconText: "󰁍"
                        tooltipText: "Back"
                        foreground: root.foreground
                        focusable: true
                        onClicked: root.navigateBack()
                    }

                    Column {
                        width: parent.width - (backButton.visible ? backButton.width + parent.spacing : 0) - headerActions.width - parent.spacing
                        spacing: Style.space(1)

                        Text {
                            width: parent.width
                            text: root.settingsOpen ? (root.selectedRow ? root.selectedRow.label : root.paneTitle()) : "Omarchy AI Bar"
                            color: root.foreground
                            font.family: root.bar ? root.bar.fontFamily : Style.font.family
                            font.pixelSize: Style.font.subtitle
                            font.bold: true
                            elide: Text.ElideRight
                        }

                        Text {
                            width: parent.width
                            text: root.settingsOpen ? (root.selectedRow ? "Provider settings" : (root.settingsPane !== "" ? "Application settings" : (root.catalogOpen ? root.disabledRows.length + " available" : root.enabledRows.length + " enabled"))) : root.configuredRows.length + (root.configuredRows.length === 1 ? " configured provider" : " configured providers")
                            color: root.muted
                            font.family: root.bar ? root.bar.fontFamily : Style.font.family
                            font.pixelSize: Style.font.caption
                            elide: Text.ElideRight
                        }
                    }

                    Row {
                        id: headerActions
                        spacing: Style.space(4)

                        PanelActionButton {
                            id: refreshAllButton
                            visible: !root.settingsOpen
                            iconText: "󰑐"
                            tooltipText: "Refresh all providers"
                            foreground: root.foreground
                            focusable: true
                            enabled: root.service !== null
                            onClicked: if (root.service)
                                root.service.refreshAll()
                        }

                        PanelActionButton {
                            id: headerAction
                            iconText: root.settingsOpen ? "󰑐" : "󰒓"
                            tooltipText: root.settingsOpen ? (root.selectedProvider !== "" ? "Refresh provider usage" : "Reload provider settings") : "Provider settings"
                            foreground: root.foreground
                            focusable: true
                            onClicked: {
                                if (root.settingsOpen && root.service) {
                                    if (root.selectedProvider !== "")
                                        root.service.refreshProvider(root.selectedProvider);
                                    else
                                        root.service.loadProviderConfig();
                                } else
                                    root.openSettings();
                            }
                        }
                    }
                }

                PanelSeparator {
                    id: headerSeparator
                    width: parent.width
                    foreground: root.foreground
                }

                Loader {
                    id: viewLoader
                    width: parent.width
                    height: Math.max(Style.space(240), panelContent.height - headerRow.height - headerSeparator.height - footerSeparator.height - footerRow.height - resizeHandle.height - panelContent.spacing * 5)
                    sourceComponent: !root.settingsOpen ? usageView : (root.selectedProvider !== "" ? providerDetailView : (root.settingsPane !== "" ? appSettingsView : (root.catalogOpen ? providerCatalogView : settingsListView)))
                }

                PanelSeparator {
                    id: footerSeparator
                    width: parent.width
                    foreground: root.foreground
                }

                Row {
                    id: footerRow
                    width: parent.width
                    spacing: Style.space(8)

                    Text {
                        width: parent.width - closeButton.width - parent.spacing
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.service && root.service.providerConfigResult !== "" ? root.service.providerConfigResult : (root.service ? root.service.connectionStatus : "Starting")
                        color: root.service && root.service.compatibilityFailure !== "" ? Color.urgent : root.muted
                        font.family: root.bar ? root.bar.fontFamily : Style.font.family
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                    }

                    Button {
                        id: closeButton
                        text: "Close"
                        foreground: root.foreground
                        focusable: true
                        onClicked: root.requestClose()
                    }
                }

                Item {
                    id: resizeHandle
                    width: parent.width
                    height: Style.space(12)

                    property real pressSceneY: 0
                    property real pressHeight: 0

                    Rectangle {
                        anchors.horizontalCenter: parent.horizontalCenter
                        anchors.verticalCenter: parent.verticalCenter
                        width: Style.space(42)
                        height: Math.max(2, Style.space(2))
                        radius: height / 2
                        color: resizeMouse.containsMouse || root.resizingPanel ? root.foreground : root.muted
                        opacity: resizeMouse.containsMouse || root.resizingPanel ? 0.9 : 0.55
                    }

                    MouseArea {
                        id: resizeMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        acceptedButtons: Qt.LeftButton
                        cursorShape: Qt.SizeVerCursor
                        preventStealing: true

                        onPressed: function (mouse) {
                            resizeHandle.pressSceneY = resizeHandle.mapToItem(null, mouse.x, mouse.y).y;
                            resizeHandle.pressHeight = popup.contentHeight;
                            root.localPanelHeight = popup.contentHeight;
                            root.resizingPanel = true;
                        }
                        onPositionChanged: function (mouse) {
                            if (!root.resizingPanel || !pressed)
                                return;
                            var sceneY = resizeHandle.mapToItem(null, mouse.x, mouse.y).y;
                            var direction = popup.barPos === "bottom" ? -1 : 1;
                            root.localPanelHeight = root.clampedPanelHeight(resizeHandle.pressHeight + (sceneY - resizeHandle.pressSceneY) * direction);
                        }
                        onReleased: root.finishPanelResize()
                        onCanceled: root.finishPanelResize()
                        onDoubleClicked: root.resetPanelHeight()
                    }
                }
            }
        }
    }

    Component {
        id: usageView

        UsageView {
            panelRoot: root
        }
    }

    Component {
        id: settingsListView

        SettingsHome {
            panelRoot: root
        }
    }

    Component {
        id: appSettingsView

        AppSettings {
            panelRoot: root
        }
    }

    Component {
        id: providerCatalogView

        ProviderCatalog {
            panelRoot: root
        }
    }

    Component {
        id: providerDetailView

        ProviderDetail {
            panelRoot: root
        }
    }
}
