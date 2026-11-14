#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-tpm-inspector"
APPLET_NAME = "TPM Inspector"
APPLET_VERSION = "0.0.4"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"

import json
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._collectors import (
    collect_capabilities,
    collect_devices,
    collect_measured_boot_with_status,
    collect_pcrs_with_status,
    discover_tpm_roots,
)
from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss


VIEW_COLUMNS = {
    "TPM Devices": [
        ("tpm", "TPM", 90, "left"),
        ("version", "Version", 90, "left"),
        ("device_node", "Device Node", 150, "left"),
        ("driver", "Driver", 150, "left"),
        ("state", "State", 100, "left"),
        ("pcr_banks", "PCR Banks", 190, "left"),
    ],
    "PCRs": [
        ("tpm", "TPM", 90, "left"),
        ("bank", "Bank", 100, "left"),
        ("pcr", "PCR", 70, "right"),
        ("value", "Value", 360, "left"),
        ("acquired", "Acquired", 190, "left"),
    ],
    "Measured Boot": [
        ("tpm", "TPM", 90, "left"),
        ("source", "Event Log Source", 340, "left"),
        ("access", "Access", 115, "left"),
        ("size", "Reported Size", 120, "left"),
        ("evidence", "Evidence", 300, "left"),
        ("acquired", "Acquired", 190, "left"),
    ],
    "Capabilities": [
        ("tpm", "TPM", 90, "left"),
        ("capability", "Capability", 230, "left"),
        ("value", "Value", 260, "left"),
        ("source", "Source", 340, "left"),
    ],
}

VIEW_TOTALS = {
    "TPM Devices": "Total TPM Devices",
    "PCRs": "Total PCR Snapshots",
    "Measured Boot": "Total Event Log Sources",
    "Capabilities": "Total Capabilities",
}


class TPMInspectorOptionsDialog(QDialog):
    """Established LinSpectacles Options treatment."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — TPM Inspector")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # Appearance
        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)

        appearance_heading = QLabel("Metadata display")
        heading_font = appearance_heading.font()
        heading_font.setBold(True)
        appearance_heading.setFont(heading_font)
        appearance_layout.addWidget(appearance_heading)

        appearance_note = QLabel(
            "Choose how the inventory and Metadata Details panes are arranged. "
            "This TPM Inspector setting is remembered."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText(
            "Vertical" if owner.details_orientation == "vertical" else "Horizontal"
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)

        shortcut_note = QLabel(
            "F3 hides/restores Metadata Details. Shift+F5 refreshes the TPM inventory. "
            "Ctrl+L toggles Horizontal/Vertical layout. Ctrl+/ opens Options. "
            "Views: Ctrl+1 = TPM Devices; Ctrl+2 = PCRs; Ctrl+3 = Measured Boot; "
            "Ctrl+4 = Capabilities."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)

        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        # Sources
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)

        sources_note = QLabel(
            "Linux interfaces used by this read-only TPM and measured-boot inspector."
        )
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, "_metadata_font", None)
        if chosen_font is not None:
            sources_text.setFont(chosen_font)
            sources_text.document().setDefaultFont(chosen_font)
            sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        else:
            font_rule = ""
        sources_text.setStyleSheet(
            "QTextEdit { "
            + font_rule
            + " background-color: #151719; color: #dcdcdc; "
              "border: 1px solid #333333; }"
        )

        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))

        cursor = sources_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in owner.sources_text().splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        sources_text.setTextCursor(cursor)
        sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        # Export
        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)

        export_heading = QLabel("Export details")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)

        export_note = QLabel(
            f"Select the {owner.current_view()} details to include in the export."
        )
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_checks = []
        for column_id, label, width, alignment in owner.columns:
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            self.export_checks.append((checkbox, column_id, label, width, alignment))
            export_layout.addWidget(checkbox)

        self.export_metadata = QCheckBox("Metadata Details")
        self.export_metadata.setChecked(False)
        export_layout.addWidget(self.export_metadata)

        export_layout.addStretch(1)
        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        # About
        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(
                    pixmap.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>TPM Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        description = QLabel(
            "A read-only LinSpectacles applet for inspecting TPM device identity, "
            "kernel-exposed PCR snapshots and measured-boot event-log evidence."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            "<a href='https://github.com/linspectacles/'>linspectacles</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "README.md")
        ).toString()
        license_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "LICENSE")
        ).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            "<a href='https://github.com/linspectacles/tpm-inspector'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, visible):
        self.owner.set_metadata_panel_visible(bool(visible), persist=True)

    def _export_selected(self):
        selected = []
        for checkbox, column_id, label, width, alignment in self.export_checks:
            if checkbox.isChecked():
                selected.append((column_id, label, width, alignment))
        if self.export_metadata.isChecked():
            selected.append(("metadata_details", "Metadata Details", 520, "left"))

        if not selected:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return

        records = []
        include_metadata = self.export_metadata.isChecked()
        for record in self.owner.get_export_records():
            exported = dict(record)
            if include_metadata:
                exported["metadata_details"] = self.owner.metadata_details_for_export(record)
            records.append(exported)

        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export yet.")
            return

        path = export_records_dialog(
            self,
            f"{APPLET_NAME} - {self.owner.current_view()}",
            records,
            columns=selected,
        )
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")


class TPMInspectorTab(BaseInspectorTab):
    NUMERIC_COLUMNS = {"pcr"}

    def __init__(self, parent=None):
        self._view_data = {name: [] for name in VIEW_COLUMNS}
        self._host_settings = {}
        self._column_visibility_callback = None
        self._active_view = None
        self._view_hidden = {}
        self._view_widths = {}
        self._selected_keys = {}
        self._secondary_choices = {"PCRs": "All Banks", "Measured Boot": "All PCRs"}
        self._column_configuring = False
        self._device_discovery = ("unavailable", "TPM sysfs has not been inspected.")
        self._event_discovery = ("unavailable", "Measured boot has not been inspected.")
        self._pcr_discovery_issues = []

        views = list(VIEW_COLUMNS)
        super().__init__(VIEW_TOTALS[views[0]], VIEW_COLUMNS[views[0]], views, parent)
        self.export_title = APPLET_NAME

        # Retain the authority shell's selector widgets; position View immediately
        # before the top-level action buttons, without changing their behaviour.
        self.category_label.setText("View:")
        filter_layout = self.layout().itemAt(1).layout()
        filter_layout.removeWidget(self.category_label)
        filter_layout.removeWidget(self.category_dropdown)
        action_index = self.dash_layout.indexOf(self.refresh_btn)
        self.dash_layout.insertWidget(action_index, self.category_label)
        self.dash_layout.insertWidget(action_index + 1, self.category_dropdown)
        try:
            self.category_dropdown.currentTextChanged.disconnect(self.filter_modules)
        except TypeError:
            pass
        self.category_dropdown.currentTextChanged.connect(self._view_changed)

        filter_status_index = filter_layout.indexOf(self.filter_status_lbl)
        self.secondary_label = QLabel("")
        self.secondary_label.setStyleSheet("font-weight: 600;")
        self.secondary_combo = QComboBox()
        self.secondary_combo.setMinimumWidth(150)
        self.secondary_combo.currentTextChanged.connect(self._secondary_changed)
        filter_layout.insertWidget(filter_status_index, self.secondary_label)
        filter_layout.insertWidget(filter_status_index + 1, self.secondary_combo)
        self.secondary_label.setVisible(False)
        self.secondary_combo.setVisible(False)

        self.details_orientation = "horizontal"
        self._load_details_orientation()

        self.metadata_panel_visible = True
        self._load_metadata_panel_visibility()

        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self._shortcuts = []
        self._install_shortcuts()

        self.table.horizontalHeader().sectionResized.connect(self._column_resized)
        self._configure_view(self.current_view(), refresh_table=False)
        self.load_modules()

    def current_view(self):
        return self.category_dropdown.currentText() or "TPM Devices"

    @staticmethod
    def _settings():
        return QSettings("brunonlinespace", "TPM Inspector")

    def _view_setting(self, view, item, default):
        raw = self._settings().value(f"views/{view}/{item}", None)
        if raw is None:
            return default
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return default
        return parsed if isinstance(parsed, type(default)) else default

    def _hidden_for_view(self, view):
        if view not in self._view_hidden:
            fallback = (self._host_settings.get("hidden_columns", [])
                        if view == "TPM Devices" else [])
            saved = self._view_setting(view, "hidden", fallback)
            known = {column[0] for column in VIEW_COLUMNS[view]}
            self._view_hidden[view] = [str(key) for key in saved if str(key) in known]
        return self._view_hidden[view]

    def _widths_for_view(self, view):
        if view not in self._view_widths:
            raw = self._view_setting(view, "widths", {})
            known = {column[0] for column in VIEW_COLUMNS[view]}
            self._view_widths[view] = {
                str(key): int(size) for key, size in raw.items()
                if str(key) in known and str(size).isdigit() and int(size) > 0
            }
        return self._view_widths[view]

    def _column_resized(self, index, _previous, current):
        if self._column_configuring or self._active_view not in VIEW_COLUMNS or current <= 0:
            return
        if 0 <= index < len(self.columns):
            key = self.columns[index][0]
            widths = self._widths_for_view(self._active_view)
            widths[key] = current
            self._settings().setValue(
                f"views/{self._active_view}/widths", json.dumps(widths)
            )

    def _remember_view_layout(self, view):
        if view not in VIEW_COLUMNS:
            return
        widths = self._widths_for_view(view)
        for index, (key, *_rest) in enumerate(VIEW_COLUMNS[view]):
            if index < self.table.columnCount() and self.table.columnWidth(index) > 0:
                widths[key] = self.table.columnWidth(index)
        self._settings().setValue(f"views/{view}/widths", json.dumps(widths))
        record = self.current_record()
        if record and record.get("_view") == view:
            self._selected_keys[view] = self._record_key(record)

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        self._host_settings = settings or {}
        self._column_visibility_callback = column_visibility_callback
        super().apply_host_settings(self._host_settings, self._columns_changed)
        if (self.current_view() == "TPM Devices"
                and not self._settings().contains("views/TPM Devices/hidden")
                and self._host_settings.get("hidden_columns")):
            known = {key for key, *_ in VIEW_COLUMNS["TPM Devices"]}
            self._view_hidden["TPM Devices"] = [
                key for key in self._host_settings["hidden_columns"] if key in known
            ]
        # Host metadata font is still host-controlled. View-specific columns
        # are owned by TPM rather than inherited across different schemas.
        self.column_visibility.apply_hidden(self._hidden_for_view(self.current_view()))
        self.column_visibility.set_changed_callback(self._columns_changed)

    def _columns_changed(self, hidden_columns):
        view = self._active_view or self.current_view()
        self._view_hidden[view] = list(hidden_columns or [])
        self._settings().setValue(
            f"views/{view}/hidden", json.dumps(self._view_hidden[view])
        )
        # Continue reporting active-view visibility to the host without
        # treating it as the visibility state of all TPM view schemas.
        self._host_settings["hidden_columns"] = list(hidden_columns or [])
        if callable(self._column_visibility_callback):
            self._column_visibility_callback(list(hidden_columns or []))

    @staticmethod
    def _record_key(record):
        if not record:
            return None
        view = record.get("_view")
        if view == "TPM Devices":
            return (view, record.get("tpm"))
        if view == "PCRs":
            return (view, record.get("tpm"), record.get("bank"), record.get("pcr"))
        if view == "Measured Boot":
            return (view, record.get("source"))
        if view == "Capabilities":
            return (view, record.get("tpm"), record.get("capability"), record.get("source"))
        return None

    def _secondary_changed(self, *_):
        view = self.current_view()
        if view in self._secondary_choices:
            self._secondary_choices[view] = self.secondary_combo.currentText()
        self.filter_modules()

    def _refresh_secondary_options(self, view):
        if view == "PCRs":
            label, fallback = "Bank:", "All Banks"
            choices = sorted(
                {str(row.get("bank", "")) for row in self._view_data[view]
                 if row.get("bank") not in (None, "", "Restricted", "Error")},
                key=str.lower,
            )
        elif view == "Measured Boot":
            label, fallback = "PCR:", "All PCRs"
            # No decoded PCR events exist in this source-only release.
            choices = []
        else:
            self.secondary_label.setVisible(False)
            self.secondary_combo.setVisible(False)
            return

        self.secondary_label.setText(label)
        self.secondary_label.setVisible(True)
        self.secondary_combo.setVisible(True)
        current = self._secondary_choices.get(view, fallback)
        blocked = self.secondary_combo.blockSignals(True)
        try:
            self.secondary_combo.clear()
            self.secondary_combo.addItem(fallback)
            self.secondary_combo.addItems(choices)
            if current in [fallback, *choices]:
                self.secondary_combo.setCurrentText(current)
            else:
                self.secondary_combo.setCurrentText(fallback)
            self._secondary_choices[view] = self.secondary_combo.currentText()
        finally:
            self.secondary_combo.blockSignals(blocked)
        self.secondary_combo.setEnabled(view != "Measured Boot")
        self.secondary_combo.setToolTip(
            "PCR filtering requires decoded event records; this view lists event-log sources only."
            if view == "Measured Boot" else ""
        )

    def _configure_view(self, view, *, refresh_table=True):
        if view not in VIEW_COLUMNS:
            return
        if self._active_view != view:
            if self._active_view in VIEW_COLUMNS:
                self._remember_view_layout(self._active_view)
            self._column_configuring = True
            try:
                self._active_view = view
                self.columns = list(VIEW_COLUMNS[view])
                self.table.setColumnCount(len(self.columns))
                self.table.setHorizontalHeaderLabels([column[1] for column in self.columns])
                saved = self._widths_for_view(view)
                for index, (key, _label, default_width, _alignment) in enumerate(self.columns):
                    self.table.setColumnWidth(index, saved.get(key, default_width))
                # Reuse the authoritative shared controller and resize modes.
                self.column_visibility.columns = list(self.columns)
                self.column_visibility._hidden = set()
                self.column_visibility.apply_hidden(self._hidden_for_view(view))
                self.column_visibility.set_changed_callback(self._columns_changed)
            finally:
                self._column_configuring = False

        self._refresh_secondary_options(view)
        self.modules_data = list(self._view_data[view])
        self.total_label_text = VIEW_TOTALS[view]
        self.stats_label.setText(f"{self.total_label_text}: {len(self.modules_data)}")
        if refresh_table:
            self.filter_modules()

    def _view_changed(self, view):
        self._configure_view(view, refresh_table=True)

    def _empty_status(self, view):
        if view == "Measured Boot":
            state, detail = self._event_discovery
            return f"Measured-boot source discovery {state}: {detail}"
        state, detail = self._device_discovery
        if state != "observed":
            return f"TPM device discovery {state}: {detail}"
        if view == "PCRs":
            if self._pcr_discovery_issues:
                return "PCR source acquisition incomplete: " + "; ".join(self._pcr_discovery_issues)
            return "No exposed PCR files were collected; this does not establish TPM readiness or bank support."
        if view == "Capabilities":
            return "No TPM capabilities are exposed by the inspected kernel interfaces."
        return "No TPM class entries found under /sys/class/tpm."

    def load_modules(self):
        try:
            device_state, device_detail, roots = discover_tpm_roots()
            devices = collect_devices(roots)
            pcrs, pcr_issues = collect_pcrs_with_status(roots)
            measured_boot, event_state, event_detail = collect_measured_boot_with_status()
            self._device_discovery = (device_state, device_detail)
            self._event_discovery = (event_state, event_detail)
            self._pcr_discovery_issues = pcr_issues
            self._view_data = {
                "TPM Devices": devices,
                "PCRs": pcrs,
                "Measured Boot": measured_boot,
                "Capabilities": collect_capabilities(devices, measured_boot),
            }
            self._configure_view(self.current_view(), refresh_table=True)
            if self.modules_data and self.current_record():
                # Selection's status is already set by on_module_select.
                pass
            elif not self.modules_data:
                self.set_status(self._empty_status(self.current_view()))
        except Exception as exc:
            self.set_status(f"Error refreshing TPM inspection data: {exc}")

    def filter_modules(self, *_):
        view = self.current_view()
        source = list(self._view_data.get(view, []))
        query = self.search_entry.text().strip().lower()
        secondary = self.secondary_combo.currentText() if view == "PCRs" else ""

        existing = self.current_record()
        selected_key = (
            self._record_key(existing)
            if existing and existing.get("_view") == view
            else self._selected_keys.get(view)
        )
        matches = []
        for record in source:
            if view == "PCRs" and secondary and secondary != "All Banks":
                if str(record.get("bank", "")) != secondary:
                    continue
            if query and not any(query in str(value).lower() for value in record.values()):
                continue
            matches.append(record)

        target_index = next(
            (index for index, record in enumerate(matches)
             if self._record_key(record) == selected_key), 0
        )
        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setCurrentCell(-1, -1)
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))

            for row_index, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self.columns):
                    value = record.get(column_id, "")
                    item = QTableWidgetItem(str(value))
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    else:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    self.table.setItem(row_index, column_index, item)
            if matches:
                self.table.setCurrentCell(target_index, 0)
                self.table.selectRow(target_index)
        finally:
            self.table.blockSignals(blocked)

        if matches:
            self.on_module_select()
        else:
            self.clear_info()
            self.set_status(self._empty_status(view) if not source else "No records match the current filters.")

        filtered = bool(query) or (view == "PCRs" and secondary not in ("", "All Banks"))
        if filtered:
            self.filter_status_lbl.setText(f"(Showing {len(matches)} of {len(source)} items)")
        else:
            self.filter_status_lbl.clear()

    def sort_by(self, column_id):
        view = self.current_view()
        reverse = self._sort_reverse.get(f"{view}::{column_id}", False)

        def key_func(record):
            value = record.get(column_id, "")
            if column_id in self.NUMERIC_COLUMNS:
                try:
                    return (0, int(value))
                except (TypeError, ValueError):
                    return (1, str(value).lower())
            return str(value).lower()

        self._view_data[view].sort(key=key_func, reverse=reverse)
        self._sort_reverse[f"{view}::{column_id}"] = not reverse
        # Do not reconstruct headers or selectors for a sort.
        self.modules_data = list(self._view_data[view])
        self.filter_modules()

    def get_export_records(self):
        return list(self._view_data.get(self.current_view(), []))

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self._render_record_details(record)
        view = record.get("_view", self.current_view())
        self._selected_keys[view] = self._record_key(record)
        if view == "TPM Devices":
            self.set_status(f"Inspecting TPM device [{record.get('tpm', 'unknown')}].")
        elif view == "PCRs":
            message = (
                f"Inspecting PCR snapshot [{record.get('tpm', 'unknown')} / {record.get('bank', '?')} / PCR {record.get('pcr', '?')}]."
            )
            if self._pcr_discovery_issues:
                message += " Other PCR acquisition issues: " + "; ".join(self._pcr_discovery_issues)
            self.set_status(message)
        elif view == "Measured Boot":
            message = "Inspecting measured-boot event-log source; binary event records are not decoded."
            if self._event_discovery[0] == "partial":
                message += " Partial source discovery: " + self._event_discovery[1]
            self.set_status(message)
        else:
            self.set_status(f"Inspecting TPM capability [{record.get('capability', 'unknown')}].")

    def _render_record_details(self, record):
        self.clear_info()
        view = record.get("_view")
        if view == "TPM Devices":
            self._render_device_details(record)
        elif view == "PCRs":
            self._render_pcr_details(record)
        elif view == "Measured Boot":
            self._render_measured_boot_details(record)
        elif view == "Capabilities":
            self._render_capability_details(record)
        else:
            self.append_info("No metadata details are available for this record.\n")
        self.info_text.moveCursor(QTextCursor.MoveOperation.Start)
        self.info_text.verticalScrollBar().setValue(0)

    def _render_device_details(self, record):
        self.append_info("--- TPM Device ---\n")
        self.append_key_value("TPM", record.get("tpm", "Not reported"))
        self.append_key_value("Version", record.get("version", "Not reported"))
        self.append_key_value("Version Source", record.get("version_source", "Not exposed"))
        self.append_key_value("State", record.get("state", "Not reported"))
        self.append_info("State reports sysfs class exposure only; TPM operational readiness is not assessed.\n")
        self.append_key_value("Driver", record.get("driver", "Not exposed"))
        self.append_key_value("Driver Source", record.get("driver_source", "Not exposed"))
        self.append_key_value("Sysfs Path", record.get("sysfs_path", "Not exposed"))
        self.append_key_value("Acquired", record.get("acquired", "Not reported"))

        self.append_info("\n--- Device Nodes ---\n")
        self.append_key_value("Raw TPM Device", record.get("raw_node", "Not reported"))
        self.append_key_value("Raw TPM Device Status", str(record.get("raw_node_state", "unknown")).capitalize())
        self.append_key_value("Resource Manager Device", record.get("rm_node", "Not reported"))
        self.append_key_value("Resource Manager Device Status", str(record.get("rm_node_state", "unknown")).capitalize())

        self.append_info("\n--- PCR Exposure ---\n")
        self.append_key_value("PCR Banks", record.get("pcr_banks", "None exposed"))
        self.append_key_value("PCR Bank Inventory State", str(record.get("pcr_banks_state", "unknown")).capitalize())
        self.append_info("PCR note: exposed PCR values are snapshots of current TPM state, not static configuration.\n")

        legacy = record.get("legacy_state") or []
        if legacy:
            self.append_info("\n--- Legacy Read-only State Attributes ---\n")
            for item in legacy:
                self.append_key_value(item.get("name", "Attribute"), item.get("value", "Not reported"))
                self.append_key_value("Source", item.get("source", "Not reported"))

        self.append_info("\n--- Inspection Boundary ---\n")
        self.append_key_value("Read-only", "Yes")
        self.append_key_value("Privilege Escalation", "None")
        self.append_key_value("TPM Commands Issued", "None")

    def _render_pcr_details(self, record):
        self.append_info("--- PCR Snapshot Evidence ---\n")
        self.append_key_value("TPM", record.get("tpm", "Not reported"))
        self.append_key_value("Hash Bank", record.get("bank", "Not reported"))
        self.append_key_value("PCR", record.get("pcr", "Not reported"))
        self.append_key_value("Value", record.get("value", "Not reported"))
        self.append_key_value("Acquired", record.get("acquired", "Not reported"))
        self.append_key_value("Source", record.get("source", "Not reported"))
        self.append_key_value("Read State", str(record.get("read_state", "unknown")).capitalize())
        self.append_info("\n--- Interpretation Boundary ---\n")
        self.append_key_value("Evidence Type", "Read-only snapshot")
        self.append_key_value("Security Verdict", "Not provided")
        self.append_info("PCR values are evidence of TPM state at acquisition time; this applet does not judge whether that state is trusted or secure.\n")

    def _render_measured_boot_details(self, record):
        self.append_info("--- Measured Boot Event-Log Source ---\n")
        self.append_key_value("TPM Directory", record.get("tpm", "Not determined"))
        self.append_key_value("Source", record.get("source", "Not reported"))
        self.append_key_value("Access", record.get("access", "Not reported"))
        self.append_key_value("Filesystem Reported Size", record.get("size", "Not available"))
        self.append_key_value("Evidence", record.get("evidence", "Not reported"))
        if record.get("has_data") is not None:
            self.append_key_value("One-byte Probe Returned Data", self._yes_no(record["has_data"]))
        if record.get("error"):
            self.append_key_value("Access Detail", record["error"])
        self.append_key_value("Acquired", record.get("acquired", "Not reported"))

        self.append_info("\n--- Interpretation Boundary ---\n")
        self.append_key_value("Inventory Unit", "Event-log source, not a decoded event")
        self.append_key_value("Event Parsing", "Not performed in 0.0.4")
        self.append_key_value("Raw Bytes Displayed", "No")
        self.append_key_value("Log Validity", "Not asserted")
        self.append_key_value("Privilege Escalation", "None")
        self.append_info("Log availability, access and filesystem-reported size are evidence only; no PCR, event type, digest or event sequence is inferred.\n")

    def _render_capability_details(self, record):
        self.append_info("--- TPM Capability ---\n")
        self.append_key_value("TPM", record.get("tpm", "Not reported"))
        self.append_key_value("Capability", record.get("capability", "Not reported"))
        self.append_key_value("Value", record.get("value", "Not reported"))
        self.append_key_value("Source", record.get("source", "Not reported"))
        self.append_info("\n--- Acquisition ---\n")
        self.append_key_value("Source Preference", "Kernel/sysfs/device-node facts")
        self.append_key_value("External TPM Tools", "Not used in 0.0.4")
        self.append_key_value("Mutating TPM Commands", "None")

    @staticmethod
    def _yes_no(value):
        return "Yes" if value else "No"

    @staticmethod
    def sources_text():
        return (
            "TPM Inspector is read-only. Its displayed facts come from these Linux interfaces.\n\n"
            "TPM device identity and stable exported attributes\n"
            "  /sys/class/tpm/\n"
            "  /sys/class/tpm/tpmN/tpm_version_major\n\n"
            "Raw TPM and resource-manager device-node presence\n"
            "  /dev/tpmN\n"
            "  /dev/tpmrmN\n\n"
            "PCR bank/value snapshots where the running kernel exposes the modern sysfs ABI\n"
            "  /sys/class/tpm/tpmN/pcr-<hash>/<number>\n\n"
            "Firmware measured-boot event-log evidence where securityfs exposes it\n"
            "  /sys/kernel/security/tpm*/binary_bios_measurements\n\n"
            "Important distinctions\n"
            "  PCR values are snapshots, not static configuration and not a security verdict.\n"
            "  Measured Boot inventories event-log sources, not decoded events; availability/access/size are reported conservatively.\n"
            "  Missing securityfs or event-log sources are reported as unavailable rather than treated as application failures.\n"
            "  Permission-restricted sources remain restricted; TPM Inspector performs no privilege escalation in 0.0.4.\n"
            "  TPM Inspector issues no provisioning, ownership, key-management, sealing, quoting, PCR-extension, NV-management or other mutating TPM commands.\n"
            "  tpm2-tools is not used in 0.0.4."
        )

    def show_options(self):
        dialog = TPMInspectorOptionsDialog(self)
        dialog.exec()

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)
        return shortcut

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)
        self._add_shortcut("Ctrl+/", self.show_options)
        self._add_shortcut("Shift+F5", self.load_modules)
        for index in range(4):
            self._add_shortcut(f"Ctrl+{index + 1}", lambda i=index: self._select_view(i))

    def _select_view(self, index):
        if 0 <= index < self.category_dropdown.count():
            self.category_dropdown.setCurrentIndex(index)

    def toggle_details_orientation(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(target, persist=True)

    def _load_metadata_panel_visibility(self):
        settings = QSettings("brunonlinespace", "TPM Inspector")
        value = settings.value("metadata_panel_visible", True)
        if isinstance(value, str):
            visible = value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            visible = bool(value)
        self.set_metadata_panel_visible(visible, persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            details_panel.setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            settings = QSettings("brunonlinespace", "TPM Inspector")
            settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def _load_details_orientation(self):
        settings = QSettings("brunonlinespace", "TPM Inspector")
        orientation = str(settings.value("details_orientation", "horizontal") or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation

        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])

        if persist:
            settings = QSettings("brunonlinespace", "TPM Inspector")
            settings.setValue("details_orientation", orientation)
            settings.sync()

    def closeEvent(self, event):
        if self._active_view in VIEW_COLUMNS:
            self._remember_view_layout(self._active_view)
        super().closeEvent(event)

    def metadata_details_for_export(self, record):
        """Render the same metadata text for one record without changing the visible pane."""
        original_info = self.info_text
        temp = QTextEdit()
        self.info_text = temp
        try:
            self._render_record_details(record)
            return temp.toPlainText()
        finally:
            self.info_text = original_info


def create_applet(parent=None):
    return TPMInspectorTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
