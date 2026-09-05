import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

Item {
    id: view

    property var panelRoot: null
    property alias scrollArea: detailScroll
    property bool errorExpanded: false

    readonly property var provider: panelRoot ? panelRoot.selectedRow : null
    readonly property var service: panelRoot ? panelRoot.service : null
    readonly property var typedSettingsDescriptor: service && provider ? service.typedSettingsDescriptor(provider.provider) : null
    readonly property var typedSettingSections: typedSections()
    readonly property var standaloneTypedActions: service && provider ? service.typedStandaloneActions(provider.provider, descriptorFeatures()) : []
    readonly property var typedAccountActions: service && provider ? service.typedAccountActions(provider.provider) : []
    readonly property bool hasTypedSettings: typedSettingsDescriptor !== null
    readonly property bool showFallbackConnection: provider && (provider.supportsEndpoint || (provider.canStoreCredential && !(service && service.hasTypedSecretControl(provider.provider))) || (provider.canLaunchLogin && !(service && service.hasImplementedTypedActionTarget(provider.provider, "login"))) || provider.canLogout || (provider.environmentKey !== "" && !(service && service.hasTypedSecretControl(provider.provider))))
    readonly property color foreground: panelRoot ? panelRoot.foreground : Color.foreground
    readonly property color muted: panelRoot ? panelRoot.muted : Qt.darker(foreground, 1.55)
    readonly property var overviewRows: provider ? [
        {
            label: "Status",
            value: provider.enabled ? provider.status : "Disabled",
            sensitivity: "public"
        },
        {
            label: "Detected",
            value: provider.detected ? "Yes" : "No",
            sensitivity: "public"
        },
        {
            label: "Source",
            value: provider.source || "Not available",
            sensitivity: "public"
        },
        {
            label: "Account",
            value: provider.account || "Not available",
            sensitivity: "personal"
        },
        {
            label: "Plan",
            value: provider.plan || "Not available",
            sensitivity: "public"
        },
        {
            label: "Authentication",
            value: provider.loginMethod || (provider.canStoreCredential ? "Secret Service" : "Automatic"),
            sensitivity: "public"
        },
        {
            label: "Updated",
            value: formatUpdated(provider.updated),
            sensitivity: "public"
        }
    ] : []

    function fontFamily() {
        return panelRoot && panelRoot.bar ? panelRoot.bar.fontFamily : Style.font.family;
    }

    function formatUpdated(value) {
        var raw = String(value || "");
        if (raw === "")
            return "Never";
        var parsed = new Date(raw);
        return isNaN(parsed.getTime()) ? raw : Qt.formatDateTime(parsed, "ddd HH:mm");
    }

    function setting(key, fallback) {
        return panelRoot ? panelRoot.setting(key, fallback) : fallback;
    }

    function privateText(value) {
        return panelRoot && typeof panelRoot.privacyText === "function" ? panelRoot.privacyText(value) : String(value || "");
    }

    function copyText(value) {
        clipboardProxy.text = privateText(value);
        clipboardProxy.selectAll();
        clipboardProxy.copy();
        clipboardProxy.deselect();
    }

    function noticeText() {
        if (!provider)
            return "";
        var error = String(provider.errorMessage || "");
        if (provider.ready && error !== "")
            return "Showing last known usage · " + error;
        if (error !== "")
            return error;
        if (provider.stale)
            return "Showing last known usage · data is stale";
        return String(provider.status || "");
    }

    function descriptorFeatures() {
        return {
            "optional-credits-and-extra-usage": setting("showOptionalCreditsAndExtraUsage", true) === true,
            "keychain-access": false
        };
    }

    function typedSections() {
        if (!service || !provider || !typedSettingsDescriptor)
            return [];
        var sections = [
            {
                id: "connection",
                title: "CONNECTION"
            },
            {
                id: "credentials",
                title: "CREDENTIALS"
            },
            {
                id: "options",
                title: "OPTIONS"
            },
            {
                id: "menu_bar",
                title: "MENU BAR"
            }
        ];
        var result = [];
        var features = descriptorFeatures();
        for (var index = 0; index < sections.length; index++) {
            var controls = service.typedControlsForSection(provider.provider, sections[index].id, features);
            if (controls.length > 0) {
                result.push({
                    id: sections[index].id,
                    title: sections[index].title,
                    controls: controls
                });
            }
        }
        return result;
    }

    function controlGap(control) {
        if (!service)
            return "unavailable";
        var item = service.typedControlItem(control);
        var gap = item && item.availability ? String(item.availability.gap || "") : "";
        if (gap === "")
            return "unavailable in this build";
        return gap.replace(/-/g, " ");
    }

    function controlInteractive(control) {
        if (!service || !provider || !service.typedControlImplemented(control))
            return false;
        var item = service.typedControlItem(control);
        return item && service.evaluateProviderSettingCondition(provider.provider, item.enabled_when, descriptorFeatures(), 0);
    }

    function credentialStatusText(slot) {
        if (!service || !provider)
            return "Status unavailable";
        switch (service.credentialSlotState(provider.provider, slot)) {
        case "configured":
            return "Stored in desktop Secret Service";
        case "not_configured":
            return "Not configured";
        case "checking":
            return "Checking secure storage…";
        case "saving":
            return "Saving securely…";
        case "deleting":
            return "Deleting…";
        default:
            return "Secure-storage status unavailable";
        }
    }

    TextEdit {
        id: clipboardProxy
        visible: false
        readOnly: true
    }

    Flickable {
        id: detailScroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: detailColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
        }

        Column {
            id: detailColumn
            width: detailScroll.width
            spacing: Style.space(12)

            BorderSurface {
                width: parent.width
                implicitHeight: heroRow.implicitHeight + Style.space(24)
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.controlSpec("normal", view.foreground, Color.accent)
                radius: Style.cornerRadius

                Row {
                    id: heroRow
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(9)

                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        width: Style.space(10)
                        height: width
                        radius: width / 2
                        color: view.provider && view.provider.configured ? Color.accent : (view.provider && view.provider.detected ? view.muted : Color.urgent)
                    }

                    Column {
                        width: parent.width - enabledSwitch.width - Style.space(29)
                        spacing: Style.space(2)

                        Text {
                            width: parent.width
                            text: view.provider ? view.provider.label : "Provider"
                            color: view.foreground
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.subtitle
                            font.bold: true
                            elide: Text.ElideRight
                        }

                        Text {
                            width: parent.width
                            text: view.provider ? (view.provider.configured ? [view.panelRoot ? view.panelRoot.accountText(view.provider.account) : view.provider.account, view.provider.plan].filter(function (value) {
                                    return value !== "";
                                }).join(" · ") : (view.provider.detected ? "Detected locally · setup incomplete" : "Not detected · manual setup")) : ""
                            color: view.muted
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.caption
                            elide: Text.ElideRight
                        }
                    }

                    ToggleSwitch {
                        id: enabledSwitch
                        anchors.verticalCenter: parent.verticalCenter
                        checked: view.provider ? view.provider.enabled : false
                        busy: view.panelRoot && view.panelRoot.service ? view.panelRoot.service.providerConfigBusy : false
                        enabled: view.provider && (view.provider.enabled || view.provider.eligibleToEnable)
                        foreground: view.foreground
                        onToggled: if (view.panelRoot && view.panelRoot.service && view.provider)
                            view.panelRoot.service.setProviderEnabled(view.provider.provider, !view.provider.enabled)
                    }
                }
            }

            Text {
                width: parent.width
                text: "OVERVIEW"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: overviewColumn.implicitHeight + Style.space(20)
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius

                Column {
                    id: overviewColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(7)

                    Repeater {
                        model: view.overviewRows

                        delegate: Row {
                            required property var modelData
                            width: overviewColumn.width

                            Text {
                                width: parent.width * 0.34
                                text: modelData.label
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                                elide: Text.ElideRight
                            }

                            Text {
                                width: parent.width * 0.66
                                text: view.panelRoot ? view.panelRoot.detailValue(modelData) : modelData.value
                                horizontalAlignment: Text.AlignRight
                                color: view.foreground
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                                elide: Text.ElideMiddle
                            }
                        }
                    }
                }
            }

            Text {
                width: parent.width
                visible: view.provider && (view.provider.errorKind !== "" || view.provider.stale)
                text: view.provider && view.provider.errorKind !== "" ? "ERROR" : "STALE DATA"
                color: view.provider && view.provider.errorKind !== "" ? Color.urgent : view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: errorContent.implicitHeight + Style.space(24)
                visible: view.provider && (view.provider.errorKind !== "" || view.provider.stale)
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.controlSpec("normal", Color.urgent, Color.urgent)
                radius: Style.cornerRadius

                Column {
                    id: errorContent
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(6)

                    Text {
                        width: parent.width
                        text: view.privateText(view.noticeText())
                        color: view.foreground
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.bodySmall
                        wrapMode: Text.WordWrap
                        maximumLineCount: view.errorExpanded ? 100 : 3
                        elide: Text.ElideRight
                    }

                    Text {
                        width: parent.width
                        visible: view.provider && view.provider.stale
                        text: view.provider ? "Last successful update " + view.formatUpdated(view.provider.updated) : ""
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                    }

                    Row {
                        spacing: Style.space(8)

                        Button {
                            text: view.errorExpanded ? "Hide details" : "Show details"
                            visible: view.noticeText().length > 160
                            foreground: view.foreground
                            focusable: true
                            onClicked: view.errorExpanded = !view.errorExpanded
                        }

                        Button {
                            text: "Copy error"
                            visible: view.provider && view.provider.errorKind !== "" && view.noticeText() !== ""
                            foreground: view.foreground
                            focusable: true
                            onClicked: view.copyText(view.noticeText())
                        }
                    }
                }
            }

            Text {
                width: parent.width
                visible: view.provider && view.provider.windows.length > 0
                text: "USAGE"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: usageColumn.implicitHeight + Style.space(24)
                visible: view.provider && view.provider.windows.length > 0
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius

                Column {
                    id: usageColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(11)

                    Repeater {
                        model: view.provider ? view.provider.windows : []

                        delegate: QuotaMetric {
                            required property var modelData
                            width: usageColumn.width
                            metric: modelData
                            panelRoot: view.panelRoot
                            foreground: view.foreground
                            muted: view.muted
                            accent: Color.accent
                            fontFamily: view.fontFamily()
                            warningThreshold: Number(view.setting("warningThreshold", 90))
                            showResetTimes: view.setting("showResetTimes", true) === true
                            showPace: view.setting("paceVisible", true) === true
                            showWarningMarkers: view.setting("quotaWarningMarkersVisible", true) === true
                            showWorkdayTicks: view.setting("workdayTicksVisible", true) === true
                        }
                    }

                    Text {
                        width: parent.width
                        visible: view.provider && view.provider.summary !== "" && (view.provider.optionalSections || []).length === 0
                        text: view.provider ? view.provider.summary : ""
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.bodySmall
                        wrapMode: Text.WordWrap
                    }
                }
            }

            Repeater {
                model: view.provider && view.setting("showOptionalCreditsAndExtraUsage", true) === true ? (view.provider.optionalSections || []) : []

                delegate: UsageExtraSection {
                    required property var modelData
                    width: detailColumn.width
                    section: modelData
                    panelRoot: view.panelRoot
                    foreground: view.foreground
                    muted: view.muted
                    accent: Color.accent
                    fontFamily: view.fontFamily()
                    warningThreshold: Number(view.setting("warningThreshold", 90))
                    showResetTimes: view.setting("showResetTimes", true) === true
                    showWarningMarkers: view.setting("quotaWarningMarkersVisible", true) === true
                }
            }

            Repeater {
                model: view.provider ? view.provider.detailSections : []

                delegate: Column {
                    id: detailSection
                    required property var modelData
                    width: detailColumn.width
                    spacing: Style.space(7)

                    Text {
                        width: parent.width
                        text: String(detailSection.modelData.title || "DETAILS").toUpperCase()
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        font.letterSpacing: 1
                    }

                    BorderSurface {
                        width: parent.width
                        implicitHeight: sectionRows.implicitHeight + Style.space(20)
                        color: Style.normalFillFor(view.foreground, Color.accent)
                        borderSpec: Border.none()
                        radius: Style.cornerRadius

                        Column {
                            id: sectionRows
                            anchors.centerIn: parent
                            width: parent.width - Style.space(24)
                            spacing: Style.space(7)

                            InlineChart {
                                width: parent.width
                                chart: detailSection.modelData.chart || null
                                sectionTitle: String(detailSection.modelData.title || "")
                                foreground: view.foreground
                                muted: view.muted
                                accent: Color.accent
                            }

                            Repeater {
                                model: Array.isArray(detailSection.modelData.rows) ? detailSection.modelData.rows : []

                                delegate: Row {
                                    required property var modelData
                                    width: sectionRows.width

                                    Text {
                                        width: parent.width * 0.56
                                        text: String(modelData.label || "")
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        width: parent.width * 0.44
                                        text: view.panelRoot ? view.panelRoot.detailValue(modelData) : [modelData.value, modelData.secondary_value].filter(function (value) {
                                            return value !== null && value !== undefined && value !== "";
                                        }).join(" · ")
                                        horizontalAlignment: Text.AlignRight
                                        color: view.foreground
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        elide: Text.ElideLeft
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Repeater {
                model: view.typedSettingSections

                delegate: Column {
                    id: typedSection

                    required property var modelData

                    width: detailColumn.width
                    spacing: Style.space(7)

                    Text {
                        width: parent.width
                        text: typedSection.modelData.title
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        font.letterSpacing: 1
                    }

                    BorderSurface {
                        width: parent.width
                        implicitHeight: typedControlsColumn.implicitHeight + Style.space(24)
                        color: Style.normalFillFor(view.foreground, Color.accent)
                        borderSpec: Border.none()
                        radius: Style.cornerRadius

                        Column {
                            id: typedControlsColumn
                            anchors.centerIn: parent
                            width: parent.width - Style.space(24)
                            spacing: Style.space(11)

                            Repeater {
                                model: typedSection.modelData.controls

                                delegate: Column {
                                    id: typedControl

                                    required property var modelData
                                    required property int index

                                    readonly property var itemData: view.service ? view.service.typedControlItem(modelData) : null
                                    readonly property string controlKind: String(modelData && modelData.kind || "")
                                    readonly property bool implemented: view.service && view.service.typedControlImplemented(modelData)
                                    readonly property bool canEdit: view.controlInteractive(modelData) && !(view.service && view.service.providerConfigBusy)
                                    readonly property var currentValue: view.service && view.provider ? view.service.providerSettingValue(view.provider.provider, modelData) : ""
                                    readonly property bool hasExplicitValue: view.service && view.provider && itemData ? view.service.providerSettingExplicit(view.provider.provider, itemData.id) : false
                                    readonly property var controlActions: view.service && view.provider ? view.service.typedActionsForControl(view.provider.provider, modelData) : []
                                    readonly property var unavailablePickerChoices: view.service ? view.service.unavailableTypedPickerOptionLabels(modelData) : []

                                    width: typedControlsColumn.width
                                    spacing: Style.space(6)
                                    opacity: implemented ? 1 : 0.64

                                    Row {
                                        width: parent.width
                                        visible: typedControl.itemData && (String(typedControl.itemData.title || "") !== "" || !typedControl.implemented)

                                        Text {
                                            width: parent.width * 0.68
                                            text: typedControl.itemData ? String(typedControl.itemData.title || "Provider setting") : "Provider setting"
                                            color: view.foreground
                                            font.family: view.fontFamily()
                                            font.pixelSize: Style.font.body
                                            font.bold: true
                                            elide: Text.ElideRight
                                        }

                                        Text {
                                            width: parent.width * 0.32
                                            text: typedControl.implemented ? (typedControl.hasExplicitValue ? "Configured" : "Default") : "Unavailable"
                                            horizontalAlignment: Text.AlignRight
                                            color: typedControl.implemented ? view.muted : Color.urgent
                                            font.family: view.fontFamily()
                                            font.pixelSize: Style.font.caption
                                            elide: Text.ElideLeft
                                        }
                                    }

                                    Text {
                                        width: parent.width
                                        visible: typedControl.itemData && String(typedControl.itemData.subtitle || "") !== ""
                                        text: typedControl.itemData ? String(typedControl.itemData.subtitle || "") : ""
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                    }

                                    Text {
                                        width: parent.width
                                        visible: !typedControl.implemented
                                        text: "Not available on Omarchy yet · " + view.controlGap(typedControl.modelData)
                                        color: Color.urgent
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                    }

                                    Text {
                                        width: parent.width
                                        visible: typedControl.implemented && !view.controlInteractive(typedControl.modelData)
                                        text: "Unavailable for the current provider selection"
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                    }

                                    Row {
                                        width: parent.width
                                        visible: typedControl.controlKind === "picker"
                                        spacing: Style.space(8)

                                        Dropdown {
                                            id: typedPicker

                                            property string configuredValue: String(typedControl.currentValue === undefined || typedControl.currentValue === null ? "" : typedControl.currentValue)

                                            width: parent.width - (typedPickerReset.visible ? typedPickerReset.width + parent.spacing : 0)
                                            showLabel: false
                                            options: view.service ? view.service.typedPickerOptions(typedControl.modelData, typedControl.implemented) : []
                                            value: configuredValue
                                            foreground: view.foreground
                                            fontFamily: view.fontFamily()
                                            enabled: typedControl.canEdit && options.length > 0
                                            opacity: enabled ? 1 : 0.58
                                            onChanged: function (nextValue) {
                                                if (view.service && view.provider && typedControl.canEdit && nextValue !== String(typedControl.currentValue))
                                                    view.service.setProviderOption(view.provider.provider, typedControl.itemData.id, nextValue);
                                            }
                                            onConfiguredValueChanged: value = configuredValue

                                            Connections {
                                                target: view.service

                                                function onProviderConfigBusyChanged() {
                                                    if (!view.service.providerConfigBusy)
                                                        typedPicker.value = typedPicker.configuredValue;
                                                }

                                                function onProviderOptionsOverridesChanged() {
                                                    typedPicker.value = typedPicker.configuredValue;
                                                }
                                            }
                                        }

                                        Button {
                                            id: typedPickerReset
                                            visible: typedControl.implemented && typedControl.hasExplicitValue
                                            text: "Default"
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: typedControl.canEdit
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.clearProviderOption(view.provider.provider, typedControl.itemData.id)
                                        }
                                    }

                                    Text {
                                        width: parent.width
                                        visible: typedControl.controlKind === "picker" && typedControl.implemented && typedControl.unavailablePickerChoices.length > 0
                                        text: "Unavailable choices in this build: " + typedControl.unavailablePickerChoices.join(", ")
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                    }

                                    Row {
                                        width: parent.width
                                        visible: typedControl.controlKind === "toggle"
                                        spacing: Style.space(8)

                                        Text {
                                            width: parent.width - typedToggle.width - (typedToggleReset.visible ? typedToggleReset.width + parent.spacing * 2 : parent.spacing)
                                            anchors.verticalCenter: parent.verticalCenter
                                            text: Boolean(typedControl.currentValue) ? "On" : "Off"
                                            color: view.muted
                                            font.family: view.fontFamily()
                                            font.pixelSize: Style.font.caption
                                        }

                                        Button {
                                            id: typedToggleReset
                                            anchors.verticalCenter: parent.verticalCenter
                                            visible: typedControl.implemented && typedControl.hasExplicitValue
                                            text: "Default"
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: typedControl.canEdit
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.clearProviderOption(view.provider.provider, typedControl.itemData.id)
                                        }

                                        ToggleSwitch {
                                            id: typedToggle
                                            anchors.verticalCenter: parent.verticalCenter
                                            checked: Boolean(typedControl.currentValue)
                                            busy: view.service ? view.service.providerConfigBusy : false
                                            enabled: typedControl.canEdit
                                            interactive: typedControl.canEdit
                                            foreground: view.foreground
                                            opacity: enabled ? 1 : 0.58
                                            onToggled: if (view.service && view.provider && typedControl.canEdit)
                                                view.service.setProviderOption(view.provider.provider, typedControl.itemData.id, !checked)
                                        }
                                    }

                                    TextField {
                                        id: typedPlainField

                                        property string savedText: String(typedControl.currentValue === undefined || typedControl.currentValue === null ? "" : typedControl.currentValue)

                                        width: parent.width
                                        visible: typedControl.controlKind === "plain_option"
                                        placeholderText: typedControl.itemData ? String(typedControl.itemData.placeholder || "") : ""
                                        password: false
                                        foreground: view.foreground
                                        enabled: typedControl.canEdit
                                        opacity: enabled ? 1 : 0.58
                                        Component.onCompleted: text = savedText
                                        onSavedTextChanged: text = savedText

                                        Connections {
                                            target: view.service

                                            function onProviderConfigBusyChanged() {
                                                if (!view.service.providerConfigBusy)
                                                    typedPlainField.text = typedPlainField.savedText;
                                            }
                                        }
                                    }

                                    Row {
                                        visible: typedControl.controlKind === "plain_option"
                                        spacing: Style.space(8)

                                        Button {
                                            text: "Save"
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: typedControl.canEdit && typedPlainField.text.trim().length > 0 && typedPlainField.text.trim().length <= 2048 && typedPlainField.text.trim() !== typedPlainField.savedText
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.setProviderOption(view.provider.provider, typedControl.itemData.id, typedPlainField.text)
                                        }

                                        Button {
                                            text: "Clear"
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: typedControl.canEdit && typedControl.hasExplicitValue
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.clearProviderOption(view.provider.provider, typedControl.itemData.id)
                                        }
                                    }

                                    Text {
                                        width: parent.width
                                        visible: typedControl.controlKind === "secret_slot" && typedControl.implemented
                                        text: typedControl.itemData ? view.credentialStatusText(typedControl.itemData.slot) : ""
                                        color: view.muted
                                        font.family: view.fontFamily()
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                    }

                                    TextField {
                                        id: typedSecretField
                                        width: parent.width
                                        visible: typedControl.controlKind === "secret_slot" && typedControl.implemented
                                        placeholderText: typedControl.itemData ? String(typedControl.itemData.placeholder || "Credential") : "Credential"
                                        password: true
                                        foreground: view.foreground
                                        enabled: typedControl.canEdit
                                        opacity: enabled ? 1 : 0.58
                                        Component.onDestruction: text = ""
                                    }

                                    Row {
                                        visible: typedControl.controlKind === "secret_slot" && typedControl.implemented
                                        spacing: Style.space(8)

                                        Button {
                                            text: "Save securely"
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: typedControl.canEdit && typedSecretField.text.length > 0 && typedSecretField.text.length <= 16384
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: {
                                                if (view.service && view.provider && view.service.storeCredentialSlot(view.provider.provider, typedControl.itemData.slot, typedSecretField.text))
                                                    typedSecretField.text = "";
                                            }
                                        }

                                        Button {
                                            text: "Delete"
                                            foreground: view.foreground
                                            focusable: true
                                            visible: view.service && view.provider && view.service.credentialSlotState(view.provider.provider, typedControl.itemData.slot) === "configured"
                                            enabled: typedControl.canEdit
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.deleteCredentialSlot(view.provider.provider, typedControl.itemData.slot)
                                        }

                                        Button {
                                            text: "Check"
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: typedControl.canEdit
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.queueCredentialSlotStatus(view.provider.provider, typedControl.itemData.slot)
                                        }
                                    }

                                    Repeater {
                                        model: typedControl.controlActions

                                        delegate: Button {
                                            required property var modelData

                                            text: String(modelData.title || "Provider action") + (view.service && view.service.availabilityImplemented(modelData.availability) ? "" : " · unavailable")
                                            foreground: view.foreground
                                            focusable: true
                                            enabled: view.service && view.service.availabilityImplemented(modelData.availability) && !(view.service && view.service.providerConfigBusy)
                                            opacity: enabled ? 1 : 0.58
                                            onClicked: if (view.service && view.provider)
                                                view.service.runTypedAction(view.provider.provider, modelData.id)
                                        }
                                    }

                                    PanelSeparator {
                                        width: parent.width
                                        visible: typedControl.index < typedSection.modelData.controls.length - 1
                                        foreground: view.foreground
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Text {
                width: parent.width
                visible: view.standaloneTypedActions.length > 0
                text: "PROVIDER ACTIONS"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: typedStandaloneActionColumn.implicitHeight + Style.space(24)
                visible: view.standaloneTypedActions.length > 0
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius

                Column {
                    id: typedStandaloneActionColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(7)

                    Repeater {
                        model: view.standaloneTypedActions

                        delegate: Column {
                            required property var modelData

                            width: typedStandaloneActionColumn.width
                            spacing: Style.space(4)
                            opacity: view.service && view.service.availabilityImplemented(modelData.availability) ? 1 : 0.64

                            Button {
                                text: String(modelData.title || "Provider action")
                                foreground: view.foreground
                                focusable: true
                                enabled: view.service && view.service.availabilityImplemented(modelData.availability) && !(view.service && view.service.providerConfigBusy)
                                opacity: enabled ? 1 : 0.58
                                onClicked: if (view.service && view.provider)
                                    view.service.runTypedAction(view.provider.provider, modelData.id)
                            }

                            Text {
                                width: parent.width
                                visible: !(view.service && view.service.availabilityImplemented(modelData.availability))
                                text: "Not available on Omarchy yet · " + String(modelData.availability && modelData.availability.gap || "unavailable").replace(/-/g, " ")
                                color: Color.urgent
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                                wrapMode: Text.WordWrap
                            }
                        }
                    }
                }
            }

            Text {
                width: parent.width
                visible: view.typedSettingsDescriptor && view.typedSettingsDescriptor.accounts
                text: "ACCOUNTS"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: typedAccountsColumn.implicitHeight + Style.space(24)
                visible: view.typedSettingsDescriptor && view.typedSettingsDescriptor.accounts
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius
                opacity: view.service && view.typedSettingsDescriptor && (view.service.availabilityImplemented(view.typedSettingsDescriptor.accounts.availability) || view.typedAccountActions.some(function (action) {
                        return view.service.availabilityImplemented(action.availability);
                    })) ? 1 : 0.64

                Column {
                    id: typedAccountsColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(5)

                    Text {
                        width: parent.width
                        text: view.typedSettingsDescriptor && view.typedSettingsDescriptor.accounts ? String(view.typedSettingsDescriptor.accounts.title || "Provider accounts") : "Provider accounts"
                        color: view.foreground
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.body
                        font.bold: true
                    }

                    Text {
                        width: parent.width
                        text: view.typedSettingsDescriptor && view.typedSettingsDescriptor.accounts ? String(view.typedSettingsDescriptor.accounts.subtitle || "") : ""
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WordWrap
                    }

                    Row {
                        width: parent.width
                        visible: view.provider && view.provider.provider === "codex"
                        spacing: Style.space(8)

                        Text {
                            width: parent.width - nativeCodexButton.width - parent.spacing
                            text: {
                                var account = view.service ? view.service.ambientCodexAccount() : null;
                                return (account && account.email !== "" ? account.email + " · native" : "Native Codex account (~/.codex)") + " · " + (account ? account.resetLabel : "Banked resets unavailable");
                            }
                            color: view.foreground
                            font.family: view.fontFamily()
                            font.pixelSize: Style.font.caption
                            elide: Text.ElideMiddle
                        }

                        Button {
                            id: nativeCodexButton
                            text: view.service && view.service.activeProviderAccounts.codex === "ambient" ? "Selected" : "Show"
                            foreground: view.foreground
                            focusable: true
                            enabled: view.service && view.service.activeProviderAccounts.codex !== "ambient" && !view.service.providerConfigBusy
                            onClicked: if (view.service)
                                view.service.activateCodexAccount("ambient")
                        }
                    }

                    Repeater {
                        model: view.provider && view.provider.provider === "codex" && view.service ? view.service.managedCodexAccounts() : []

                        delegate: Column {
                            required property var modelData
                            width: typedAccountsColumn.width
                            spacing: Style.space(4)

                            PanelSeparator {
                                width: parent.width
                                foreground: view.foreground
                            }

                            Text {
                                width: parent.width
                                text: modelData.email !== "" ? modelData.email : modelData.id
                                color: view.foreground
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                                font.bold: modelData.active
                                elide: Text.ElideMiddle
                            }

                            Text {
                                width: parent.width
                                text: [modelData.plan, modelData.state, modelData.resetLabel, modelData.active ? "active" : ""].filter(function (value) {
                                    return value !== "";
                                }).join(" · ")
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                                elide: Text.ElideRight
                            }

                            Row {
                                spacing: Style.space(7)

                                Button {
                                    text: modelData.active ? "Selected" : "Show"
                                    foreground: view.foreground
                                    focusable: true
                                    enabled: view.service && modelData.enabled && !modelData.active && !view.service.providerConfigBusy
                                    onClicked: if (view.service)
                                        view.service.activateCodexAccount(modelData.id)
                                }

                                Button {
                                    text: "Remove"
                                    foreground: view.foreground
                                    focusable: true
                                    enabled: view.service && !view.service.providerConfigBusy
                                    onClicked: if (view.service)
                                        view.service.removeCodexAccount(modelData.id)
                                }
                            }
                        }
                    }

                    Text {
                        width: parent.width
                        visible: !(view.service && view.typedSettingsDescriptor && view.service.availabilityImplemented(view.typedSettingsDescriptor.accounts.availability))
                        text: "Multiple managed accounts are not available in this build"
                        color: Color.urgent
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WordWrap
                    }

                    Repeater {
                        model: view.typedAccountActions

                        delegate: Button {
                            required property var modelData

                            text: String(modelData.title || "Provider action") + (view.service && view.service.availabilityImplemented(modelData.availability) ? "" : " · unavailable")
                            foreground: view.foreground
                            focusable: true
                            enabled: view.service && view.service.availabilityImplemented(modelData.availability) && !(view.service && view.service.providerConfigBusy)
                            opacity: enabled ? 1 : 0.58
                            onClicked: if (view.service && view.provider)
                                view.service.runTypedAction(view.provider.provider, modelData.id)
                        }
                    }
                }
            }

            Text {
                width: parent.width
                visible: view.showFallbackConnection
                text: view.hasTypedSettings ? "LOGIN & FALLBACK" : "CONNECTION"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: connectionColumn.implicitHeight + Style.space(24)
                visible: view.showFallbackConnection
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius

                Column {
                    id: connectionColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(9)

                    Text {
                        width: parent.width
                        text: view.provider ? view.provider.configurationHint : ""
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.bodySmall
                        wrapMode: Text.WordWrap
                    }

                    Text {
                        width: parent.width
                        visible: view.provider && view.provider.supportsEndpoint
                        text: "API ENDPOINT"
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        font.letterSpacing: 1
                    }

                    TextField {
                        id: endpointField

                        property string providerKey: view.provider ? String(view.provider.provider || "") : ""
                        property string savedEndpoint: view.provider ? String(view.provider.endpoint || "") : ""

                        width: parent.width
                        visible: view.provider && view.provider.supportsEndpoint
                        placeholderText: "https://api.example.com"
                        password: false
                        foreground: view.foreground
                        enabled: !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                        Component.onCompleted: text = savedEndpoint
                        onProviderKeyChanged: text = savedEndpoint
                        onSavedEndpointChanged: text = savedEndpoint
                    }

                    Row {
                        visible: view.provider && view.provider.supportsEndpoint
                        spacing: Style.space(8)

                        Button {
                            text: "Save endpoint"
                            foreground: view.foreground
                            focusable: true
                            enabled: endpointField.text.trim().length > 0 && endpointField.text.trim().length <= 2048 && endpointField.text.trim() !== endpointField.savedEndpoint && !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                            onClicked: if (view.panelRoot && view.panelRoot.service && view.provider)
                                view.panelRoot.service.setProviderEndpoint(view.provider.provider, endpointField.text)
                        }

                        Button {
                            text: "Clear"
                            foreground: view.foreground
                            focusable: true
                            enabled: endpointField.savedEndpoint !== "" && !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                            onClicked: if (view.panelRoot && view.panelRoot.service && view.provider)
                                view.panelRoot.service.clearProviderEndpoint(view.provider.provider)
                        }
                    }

                    Text {
                        width: parent.width
                        visible: view.provider && view.provider.supportsEndpoint
                        text: "Saved for this provider's default route. A service environment override takes precedence and is not shown here."
                        color: view.muted
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WordWrap
                    }

                    Text {
                        width: parent.width
                        visible: view.provider && view.provider.environmentKey !== "" && !view.provider.canStoreCredential && !(view.service && view.service.hasTypedSecretControl(view.provider.provider))
                        text: view.provider ? view.provider.environmentKey : ""
                        color: view.foreground
                        font.family: view.fontFamily()
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WrapAnywhere
                    }

                    TextField {
                        id: credentialField
                        width: parent.width
                        visible: view.provider && view.provider.canStoreCredential && !(view.service && view.service.hasTypedSecretControl(view.provider.provider))
                        placeholderText: view.provider && view.provider.environmentKey !== "" ? "API key or access token" : "Session credential"
                        password: true
                        foreground: view.foreground
                    }

                    Row {
                        spacing: Style.space(8)

                        Button {
                            visible: view.provider && view.provider.canStoreCredential && !(view.service && view.service.hasTypedSecretControl(view.provider.provider))
                            text: "Save securely"
                            foreground: view.foreground
                            focusable: true
                            enabled: credentialField.text.length > 0 && !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                            onClicked: if (view.panelRoot && view.panelRoot.service && view.provider && view.panelRoot.service.storeManualCredential(view.provider.provider, credentialField.text))
                                credentialField.text = ""
                        }

                        Button {
                            visible: view.provider && view.provider.canLaunchLogin && !(view.service && view.service.hasImplementedTypedActionTarget(view.provider.provider, "login"))
                            text: view.provider && view.provider.provider === "copilot" ? "Sign in with GitHub" : "Open login"
                            foreground: view.foreground
                            focusable: true
                            onClicked: if (view.panelRoot && view.panelRoot.service && view.provider)
                                view.panelRoot.service.launchLogin(view.provider.provider)
                        }

                        Button {
                            visible: view.provider && view.provider.canLogout
                            text: "Sign out"
                            foreground: view.foreground
                            focusable: true
                            enabled: !(view.panelRoot && view.panelRoot.service && view.panelRoot.service.providerConfigBusy)
                            onClicked: if (view.panelRoot && view.panelRoot.service && view.provider)
                                view.panelRoot.service.logoutProvider(view.provider.provider)
                        }
                    }
                }
            }

            Text {
                width: parent.width
                text: "MENU BAR & WARNINGS"
                color: view.muted
                font.family: view.fontFamily()
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1
            }

            BorderSurface {
                width: parent.width
                implicitHeight: optionsColumn.implicitHeight + Style.space(24)
                color: Style.normalFillFor(view.foreground, Color.accent)
                borderSpec: Border.none()
                radius: Style.cornerRadius

                Column {
                    id: optionsColumn
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    spacing: Style.space(10)

                    Row {
                        width: parent.width

                        Column {
                            width: parent.width - barProviderButton.width
                            spacing: Style.space(2)

                            Text {
                                text: "Show in menu bar"
                                color: view.foreground
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.body
                            }
                            Text {
                                text: view.setting("preferredProvider", "Highest usage") === (view.provider ? view.provider.label : "") ? "Selected provider" : "Currently follows " + view.setting("preferredProvider", "Highest usage")
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                            }
                        }

                        Button {
                            id: barProviderButton
                            text: view.setting("preferredProvider", "Highest usage") === (view.provider ? view.provider.label : "") ? "Selected" : "Select"
                            foreground: view.foreground
                            focusable: true
                            enabled: view.provider && view.provider.enabled
                            onClicked: if (view.panelRoot && view.provider)
                                view.panelRoot.persistSetting("preferredProvider", view.provider.label)
                        }
                    }

                    PanelSeparator {
                        width: parent.width
                        foreground: view.foreground
                    }

                    Row {
                        width: parent.width

                        Column {
                            width: parent.width - warningButton.width
                            spacing: Style.space(2)

                            Text {
                                text: "Quota warning"
                                color: view.foreground
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.body
                            }
                            Text {
                                text: "Warn at " + Number(view.setting("warningThreshold", 90)) + "% used"
                                color: view.muted
                                font.family: view.fontFamily()
                                font.pixelSize: Style.font.caption
                            }
                        }

                        Button {
                            id: warningButton
                            text: "Configure"
                            foreground: view.foreground
                            focusable: true
                            onClicked: if (view.panelRoot)
                                view.panelRoot.openSettingsPane("notifications")
                        }
                    }
                }
            }
        }
    }
}
