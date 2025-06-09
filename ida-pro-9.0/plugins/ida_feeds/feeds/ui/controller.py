import os
import pathlib
import shutil
import ida_undo
import ida_libfuncs
import ida_kernwin
import ida_nalt

from collections import Counter
from PyQt5.QtCore import *
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import *

from feeds.env import *
from feeds.core import log
from feeds.core.idahelper import IDA
from feeds.core.signals import WorkerSignals, probe_signals, ui_signals
from feeds.ui.view import *

import importlib
try:
    sequential_probe_lib = importlib.import_module('feeds.core.sequential')
except ImportError:
    sequential_probe_lib = None
try:
    parallel_probe_lib = importlib.import_module('feeds.core.parallel')
except ImportError:
    parallel_probe_lib = None


class ParallelProbe:
    def __init__(self):
        self.setting_label = 'Parallel probing'
        self.index = 1
        self.lib = parallel_probe_lib
        self.default = parallel_probe_lib is not None

class SequentialProbe:
    def __init__(self):
        self.setting_label = 'Sequential probing'
        self.index = 0
        self.lib = sequential_probe_lib
        self.default = parallel_probe_lib is None

class Manager:
    def __init__(self, idb, undo_handler = None, redo_handler = None):
        self.probe = None
        self.idb = idb
        self.opened_directory = IDA.get_ida_sig_dir()
        self.filter_pattern = ''
        self.filter_dir = ''
        self.filter_matches = False
        self.view = FeedsView()

        # Optional undo / redo actions
        self.undo_handler = undo_handler
        self.redo_handler = redo_handler

        self.user_signatures_controller = SignaturesController(self.view.panel_user_signatures,
                                                               undo_handler=self.undo_handler,
                                                               redo_handler=self.redo_handler)

        self.job_completed_units = 0
        self.job_total_units = 0
        self.state_counter = Counter({item_state: 0 for item_state in SignatureItemState})
        self.thread_pool = QThreadPool.globalInstance()
        self.probe_signals = WorkerSignals()

        self.clean_cache()
        self.connect_callbacks()

    def clear_data(self):
        self.user_signatures_controller.clear_data()

    def connect_callbacks(self):
        self.view.panel_folders.button_open.clicked.connect(self.open_directory_dialog)
        self.view.panel_folders.folders.selectionModel().selectionChanged.connect(self.on_folder_selection_changed)


        probe_signals.update.connect(self.on_process_update, Qt.QueuedConnection)
        probe_signals.start.connect(self.on_process_start, Qt.QueuedConnection)
        probe_signals.finish.connect(self.on_process_finish, Qt.QueuedConnection)

    def on_folder_selection_changed(self, selected, deselected):
        selected_type = None
        deselected_type = None
        path = ''

        for index in selected.indexes():
            if index.isValid():
                selected_type = self.view.panel_folders.folders.model.itemFromIndex(index).data(
                    self.view.panel_folders.folders.model.ROLE_ITEM_TYPE)
                path = self.view.panel_folders.folders.model.itemFromIndex(index).data(
                    self.view.panel_folders.folders.model.ROLE_ITEM_PATH)
                break

        for index in deselected.indexes():
            if index.isValid():
                deselected_type = self.view.panel_folders.folders.model.itemFromIndex(index).data(
                    self.view.panel_folders.folders.model.ROLE_ITEM_TYPE)
                break

        if selected_type != deselected_type:
            if deselected_type == self.view.panel_folders.folders.model.ITEM_USER_SIGNATURES:
                self.user_signatures_controller.disconnect_temp_signals()

            if selected_type == self.view.panel_folders.folders.model.ITEM_USER_SIGNATURES:
                self.view.set_visible(self.view.panel_user_signatures)
                self.user_signatures_controller.connect_temp_signals()

        if path != '':
            ui_signals.filter_path.emit(os.path.abspath(path))

    def on_process_update(self, value):
        self.job_completed_units += value
        self.view.progress_dialog.progress_bar.setValue(self.job_completed_units)
        if self.job_completed_units >= self.job_total_units:
            self.view.progress_dialog.hide()
            ui_signals.process_finished.emit()

    def on_process_start(self, value):
        self.job_completed_units = 0
        self.job_total_units = value
        self.view.progress_dialog.progress_bar.setValue(0)
        self.view.progress_dialog.progress_bar.setMaximum(value)
        self.view.progress_dialog.show()

    def on_process_finish(self):
        self.view.progress_dialog.hide()

    def on_process_error(self, e):
        log.error(e)
        self.view.progress_dialog.hide()

    def refresh_content(self, force_refresh: bool = False):
        ui_signals.refresh.emit(force_refresh)

    def populate_model(self, directory = IDA.get_ida_sig_dir()):
        self.view.panel_folders.folders.model.set_user_path(directory)
        self.user_signatures_controller.populate_model(directory)

        self.select_user_folder()

    def select_user_folder(self):
        first_index = self.view.panel_folders.folders.model.index(0, 0)
        self.view.panel_folders.folders.setCurrentIndex(first_index)
        self.view.panel_folders.folders.selectionModel().select(first_index,
                                                                QItemSelectionModel.Select |
                                                                QItemSelectionModel.Rows)
        self.view.panel_folders.folders.setFocus()
        self.view.panel_folders.folders.expandAll()

    def open_directory_dialog(self):
        if type(self.view.parent) is QWidget:
            parent=self.view.parent
        else:
            parent=self.view

        directory = QFileDialog.getExistingDirectory(parent=parent, caption="Select Directory", directory=IDA.get_ida_sig_dir())
        if directory:
            self.user_signatures_controller.populate_model(directory)
            self.view.panel_folders.folders.model.set_user_path(directory)
            self.select_user_folder()

    def clean_cache(self):
        try:
            shutil.rmtree(os.path.join(CACHE_DIR, 'procs'))
        except Exception as e:
            pass

class SignaturesController:
    def __init__(self, view:SignaturesPanel, undo_handler = None, redo_handler = None):
        self.probe = None
        self.opened_directory = ''
        self.filter_pattern = ''
        self.filter_dir = ''
        self.filter_matches = False
        self.view = view
        self.state_counter = Counter({item_state: 0 for item_state in SignatureItemState})
        self.thread_pool = QThreadPool.globalInstance()

        # Set up model
        self.analyze_results = []
        self.applied_results = {}
        self.loaded_signatures = {}

        # Set up probe settings
        self.parallel_probe = ParallelProbe()
        self.sequential_probe = SequentialProbe()
        if self.parallel_probe.lib is not None:
            self.controls_setting_probe.insertItem(self.parallel_probe.index, self.parallel_probe.setting_label, self.parallel_probe)
        else:
            self.controls_setting_probe.setDisabled(True)
        if self.sequential_probe.lib is not None:
            self.controls_setting_probe.insertItem(self.sequential_probe.index, self.sequential_probe.setting_label, self.sequential_probe)
        if self.controls_setting_probe.count() > 0:
            if self.parallel_probe.default:
                probe_index = self.parallel_probe.index
            else:
                probe_index = self.sequential_probe.index
            self.controls_setting_probe.setCurrentIndex(probe_index)
            self.probe_wrapper = self.controls_setting_probe.itemData(probe_index, role=Qt.UserRole)
            self.probe = self.probe_wrapper.lib.SignatureProbe()
        else:
            self.controls_setting_probe.setDisabled(True)

        self.filter_matches = self.view.signatures.hide_no_matches_action.isChecked()

        # Optional undo / redo actions
        self.undo_handler = undo_handler
        self.redo_handler = redo_handler
        if self.undo_handler is not None:
            self.signatures_view.context_menu.addSeparator()
            self.signatures_view.undo_action = QAction("Undo", self.signatures_view)
            self.signatures_view.context_menu.addAction(self.signatures_view.undo_action)
            self.signatures_view.undo_shortcut = QShortcut(QKeySequence("Ctrl+Z"), self.signatures_view)
            self.signatures_view.undo_shortcut.activated.connect(self.undo_handler)
        if self.redo_handler is not None:
            self.signatures_view.redo_action = QAction("Redo", self.signatures_view)
            self.signatures_view.redo_shortcut = QShortcut(QKeySequence("Ctrl+Shift+Z"), self.signatures_view)
            self.signatures_view.redo_shortcut.activated.connect(self.redo_handler)
            self.signatures_view.context_menu.addAction(self.signatures_view.redo_action)

        self.connect_signals()

    @property
    def signatures_view(self):
        return self.view.signatures

    @property
    def signatures_model(self):
        return self.view.signatures.model

    @property
    def signatures_proxy(self):
        return self.view.signatures.proxy_model

    @property
    def controls_button_apply(self):
        return self.view.controls.button_apply

    @property
    def controls_button_probe(self):
        return self.view.controls.button_probe

    @property
    def controls_setting_probe(self):
        return self.view.controls.probe_setting

    @property
    def controls_filter(self):
        return self.view.controls.filter

    def clear_data(self):
        self.analyze_results.clear()
        self.applied_results.clear()
        self.loaded_signatures.clear()

    def add_items(self, cdir):
        fs = os.walk(top=pathlib.Path(cdir), followlinks=True)
        for root, dirs, files in fs:
            for f in files:
                _, ext = os.path.splitext(f)
                if ext == '.sig':
                    fpath = os.path.realpath(os.path.join(root, f))
                    # check if the sig file is a startup signature one
                    header = ida_libfuncs.idasgn_header_t()
                    libname = None
                    try:
                        libname = ida_libfuncs.get_idasgn_header_by_short_name(header, fpath)
                    except:
                        pass
                    if libname is None or (header.flags & ida_libfuncs.LS_STARTUP) != 0:
                        continue # startup signature or invalid file
                    self.loaded_signatures[os.path.realpath(fpath)] = {"matches": -1, "state": SignatureItemState.NONE}

        for key, value in self.loaded_signatures.items():
            root_dir = os.path.realpath(cdir)
            library_name = IDA.get_sig_name(key)
            self.view.signatures.add_row(root_dir, key, library_name, value["matches"], value["state"])

    def connect_signals(self):
        self.signatures_view.hide_no_matches_action.triggered.connect(self.on_hide_no_matches)
        self.signatures_view.analysis_action.triggered.connect(self.on_click_analyze)
        self.signatures_view.apply_action.triggered.connect(self.on_click_apply)
        self.signatures_view.expand_all_action.triggered.connect(self.on_click_expand_all)
        self.signatures_view.collapse_all_action.triggered.connect(self.on_click_collapse_all)
        self.signatures_view.customContextMenuRequested.connect(self.open_context_menu)
        self.signatures_view.selectionModel().selectionChanged.connect(self.on_selection_changed)
        self.signatures_model.dataChanged.connect(self.on_data_changed)

        self.controls_filter.editingFinished.connect(self.filter_items)
        self.controls_setting_probe.currentIndexChanged.connect(self.on_probe_setting_changed)
        self.controls_button_probe.clicked.connect(self.on_click_analyze)
        self.controls_button_apply.clicked.connect(self.on_click_apply)

        if self.undo_handler is not None and self.signatures_view.undo_action is not None:
            self.signatures_view.undo_action.triggered.connect(self.undo_handler)
        if self.redo_handler is not None and self.signatures_view.redo_action is not None:
            self.signatures_view.redo_action.triggered.connect(self.redo_handler)

    def connect_temp_signals(self):
        probe_signals.result.connect(self.on_process_result, Qt.QueuedConnection)
        ui_signals.process_finished.connect(self.on_process_finished, Qt.QueuedConnection)
        ui_signals.filter_path.connect(self.apply_filters, Qt.QueuedConnection)
        ui_signals.refresh.connect(self.refresh_content, Qt.QueuedConnection)

    def disconnect_temp_signals(self):
        probe_signals.result.disconnect(self.on_process_result)
        ui_signals.process_finished.disconnect(self.on_process_finished)
        ui_signals.filter_path.disconnect(self.apply_filters)
        ui_signals.refresh.disconnect(self.refresh_content)

    def disconnect_signals(self):
        self.signatures_view.hide_no_matches_action.triggered.disconnect(self.on_hide_no_matches)
        self.signatures_view.analysis_action.triggered.disconnect(self.on_click_analyze)
        self.signatures_view.apply_action.triggered.disconnect(self.on_click_apply)
        self.signatures_view.expand_all_action.triggered.disconnect(self.on_click_expand_all)
        self.signatures_view.collapse_all_action.triggered.disconnect(self.on_click_collapse_all)
        self.signatures_view.customContextMenuRequested.disconnect(self.open_context_menu)
        self.signatures_view.selectionModel().selectionChanged.disconnect(self.on_selection_changed)
        self.signatures_model.dataChanged.disconnect(self.on_data_changed)

        self.controls_filter.editingFinished.disconnect(self.filter_items)
        self.controls_setting_probe.currentIndexChanged.disconnect(self.on_probe_setting_changed)
        self.controls_button_probe.clicked.disconnect(self.on_click_analyze)
        self.controls_button_apply.clicked.disconnect(self.on_click_apply)

        if self.undo_handler is not None and self.signatures_view.undo_action is not None:
            self.signatures_view.undo_action.triggered.disconnect(self.undo_handler)
        if self.redo_handler is not None and self.signatures_view.redo_action is not None:
            self.signatures_view.redo_action.triggered.disconnect(self.redo_handler)

    def set_actions_state(self):
        selected_states = []
        selected_indexes = self.view.signatures.selectionModel().selectedIndexes()
        for index in selected_indexes:
            if index.column() == 0:
                row_state = self.get_row_state(index)
                if row_state is not None:
                    selected_states.append(SignatureItemState.from_value(row_state))

        self.state_counter = Counter({item_state: 0 for item_state in SignatureItemState})
        self.state_counter.update(selected_states)

        self.view.signatures.analysis_action.setEnabled(True)
        self.view.signatures.apply_action.setEnabled(True)
        self.view.controls.button_probe.setEnabled(True)
        self.view.controls.button_apply.setEnabled(True)
        if self.state_counter[SignatureItemState.NONE] == 0:
            self.view.signatures.analysis_action.setDisabled(True)
            self.view.controls.button_probe.setDisabled(True)
            if self.state_counter[SignatureItemState.VERIFIED] == 0:
                self.view.signatures.apply_action.setDisabled(True)
                self.view.controls.button_apply.setDisabled(True)

        self.controls_button_probe.setText(f'{self.probe.label()} ({self.state_counter[SignatureItemState.NONE]})')
        self.view.signatures.analysis_action.setText(f'{self.probe.label()} ({self.state_counter[SignatureItemState.NONE]})')
        self.controls_button_apply.setText(f'Apply signatures ({self.state_counter[SignatureItemState.NONE] + self.state_counter[SignatureItemState.VERIFIED]})')
        self.view.signatures.apply_action.setText(f'Apply signatures ({self.state_counter[SignatureItemState.NONE] + self.state_counter[SignatureItemState.VERIFIED]})')

        if self.view.signatures.undo_action is not None:
            undo_label = ida_undo.get_undo_action_label()
            self.view.signatures.undo_action.setEnabled(undo_label is not None)
            self.view.signatures.undo_action.setText("Undo " + ("" if undo_label is None else undo_label) )

        if self.view.signatures.redo_action is not None:
            redo_label = ida_undo.get_redo_action_label()
            self.view.signatures.redo_action.setEnabled(redo_label is not None)
            self.view.signatures.redo_action.setText("Redo " + ("" if redo_label is None else redo_label))

    def on_data_changed(self, tl, br, ro):
        self.set_actions_state()

    def on_selection_changed(self, selected, deselected):
        self.set_actions_state()

    def on_hide_no_matches(self):
        self.filter_matches = self.view.signatures.hide_no_matches_action.isChecked()
        self.apply_filters()

    def on_probe_setting_changed(self, index):
        probe = self.controls_setting_probe.itemData(index, Qt.UserRole)
        if probe.lib is None:
            self.controls_setting_probe.setCurrentIndex(self.probe_wrapper.index)
        else:
            self.probe_wrapper = probe
            self.probe = self.probe_wrapper.lib.SignatureProbe()

    def open_context_menu(self, position):
        self.set_actions_state()
        self.view.signatures.context_menu.exec_(self.view.signatures.viewport().mapToGlobal(position))

    def apply_filters(self, filter_dir=None):
        if filter_dir is not None:
            self.filter_dir = filter_dir
        if self.filter_dir == self.opened_directory:
            self.filter_dir = ''
        self.signatures_proxy.applyFilters(self.filter_pattern, self.filter_dir, self.filter_matches)

    def filter_items(self):
        self.filter_pattern = self.controls_filter.text()
        self.apply_filters(self.filter_pattern)

    def get_row_state(self, index):
        if index.column() == 0:
            source_index = self.signatures_proxy.mapToSource(index)
            if source_index.isValid():
                state_index = source_index.siblingAtColumn(3)
                return self.signatures_model.data(state_index, Qt.UserRole)

        return None

    def get_selected_items(self, allow_state: []):
        sig_rows = []
        selected_indexes = self.signatures_view.selectionModel().selectedIndexes()
        for index in selected_indexes:
            if index.column() == 0:
                source_index = self.signatures_proxy.mapToSource(index)
                if source_index.isValid():
                    source_data = self.signatures_model.data(source_index, Qt.UserRole)
                    if self.get_row_state(index) in allow_state:
                        sig_rows.append({'path': source_data, 'row': source_index})

        return sig_rows

    def on_process_finished(self):
        self.sort_items()

    def sort_items(self):
        self.signatures_view.sortByColumn(0, Qt.AscendingOrder)
        self.signatures_view.sortByColumn(2, Qt.DescendingOrder)
        self.signatures_view.sortByColumn(3, Qt.DescendingOrder)

    def on_click_apply(self):
        items = self.get_selected_items([SignatureItemState.NONE.value_int, SignatureItemState.VERIFIED.value_int])
        IDA.apply_sig_list(items)

        if len(items) > 1:
            self.signatures_view.selectionModel().clearSelection()
            self.signatures_view.setCurrentIndex(QModelIndex())

        ida_kernwin.request_refresh(ida_kernwin.IWID_SIGNS)

    def on_click_expand_all(self):
        self.signatures_view.expandAll()

    def on_click_collapse_all(self):
        self.signatures_view.collapseAll()

    def get_item_from_proxy(self, row, column):
        proxy_index = self.signatures_proxy.index(row, column)
        source_index = self.signatures_proxy.mapToSource(proxy_index)
        return self.signatures_model.itemFromIndex(source_index)

    def update_results(self, row):
        item_sig = self.signatures_view.get_item_from_source(row, 0)
        item_sig.removeRows(0, item_sig.rowCount())
        sig_file = item_sig.data(Qt.UserRole)
        row_state = SignatureItemState.NONE
        total_matches = 0

        # Check if it is in the applied items
        if sig_file in self.applied_results:
            total_matches = self.applied_results[sig_file]["matches"]
            row_state = SignatureItemState.APPLIED

        # Check if it is in the analyzed items if is not in the applied ones
        if row_state == SignatureItemState.NONE:
            for analyzed_item in self.analyze_results:
                if 'sig_file' in analyzed_item and analyzed_item['sig_file'] == sig_file:
                    total_matches = len(analyzed_item['matched_functions'])
                    row_state = SignatureItemState.VERIFIED
                    for fun_match in analyzed_item['matched_functions']:
                        fun_item = QStandardItem(fun_match['item'])
                        fun_item.setSelectable(False)
                        fun_item.setEditable(False)
                        item_sig.appendRow(fun_item)
                    break

        # Set the state (none, verified, applied)
        self.signatures_view.set_row_state(row, row_state)

        # Set number of matches
        self.signatures_view.get_item_from_source(row, 2).setData(int(total_matches), Qt.UserRole)
        self.signatures_view.get_item_from_source(row, 2).setData(str(total_matches), Qt.DisplayRole)

        # Set description
        self.signatures_view.get_item_from_source(row, 3).setData(row_state.value_int, Qt.UserRole)
        self.signatures_view.get_item_from_source(row, 3).setData(row_state.description, Qt.DisplayRole)

    def refresh_content(self, force_refresh: bool = False):
        applied_current = IDA.get_applied_sigs_dict(intersect_with=self.loaded_signatures)
        if not force_refresh and applied_current == self.applied_results:
            return
        self.applied_results = applied_current
        for row in range(self.signatures_model.rowCount()):
            index = self.signatures_model.index(row, 0)
            if index is not None and index.isValid():
                self.update_results(index)
        self.sort_items()

    def on_click_analyze(self):
        sig_rows = self.get_selected_items([SignatureItemState.NONE.value_int])
        if len(sig_rows) != 0:
            self.process(sig_rows)

        if len(sig_rows) > 1:
            self.signatures_view.selectionModel().clearSelection()
            self.signatures_view.setCurrentIndex(QModelIndex())

    def populate_model(self, directory = IDA.get_ida_sig_dir()):
        self.opened_directory = directory
        self.loaded_signatures = {}
        self.signatures_model.removeRows(0, self.signatures_model.rowCount())  # Clear the model
        self.add_items(os.path.realpath(directory))
        self.signatures_view.header.resizeSections(QHeaderView.ResizeToContents)
        self.signatures_view.collapseAll()  # Collapse all groups for easily viewing the matching numbers
        self.view.show_empty(self.signatures_model.rowCount() == 0)

        # Fill the numbers for already applied signatures
        self.refresh_content(force_refresh=True)

    def process(self, signatures):
        self.probe.process(signatures)

    def on_process_result(self, result, row):
        matched_functions = [ {"item": result["matched_functions"][i]} for i in range(len(result["matched_functions"])) ]
        self.analyze_results.append({'sig_file': result['signature'], 'matched_functions': matched_functions})
        self.update_results(row)
