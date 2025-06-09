dependencies_loaded = True
failed_dependency = ''
try:
    import sys
    import idapro
    import ida_kernwin
    import ida_auto
    import ida_undo
    from PyQt5.QtCore import QRunnable, pyqtSlot, Qt, QTimer
    from feeds import env
    from feeds.ui.view import FeedsView
    from feeds.ui.controller import Manager
    # from ui.view import FeedsView
    # from ui.controller import Manager
    from PyQt5.QtWidgets import (
        QApplication,
        QFileDialog,
        QMessageBox,
        QShortcut, QMainWindow, QWidget, QStyleFactory,
)
    from PyQt5.QtGui import QKeySequence, QCursor
except ImportError as e:
    dependencies_loaded = False  # Set flag if a dependency fails
    failed_dependency = e.name   # Store the name of the missing dependency
    if not dependencies_loaded:
        print(f"IDA Feeds ({__file__}) cannot start, requires {failed_dependency}.\n")
        sys.exit(1)


class AppMainWindow(QMainWindow):
    REFRESH_TIME = 500
    WINDOW_TITLE = 'IDA Feeds'
    def __init__(self):
        super().__init__()

        self.setWindowTitle(self.WINDOW_TITLE)
        self.mgr = Manager(env.IDB_PATH, self.on_undo, self.on_redo)
        self.widget = QWidget()
        self.widget.setLayout(self.mgr.view.layout)
        self.setCentralWidget(self.widget)
        self.idb_path = None
        self.idle_callback = None

    def on_undo(self):
        ida_undo.perform_undo()

    def on_redo(self):
        ida_undo.perform_redo()

    def on_refresh_timer(self):
        ida_auto.auto_wait()
        if self.mgr is not None and ida_kernwin.is_refresh_requested(ida_kernwin.IWID_SIGNS):
            ida_kernwin.request_refresh(ida_kernwin.IWID_ALL, False)
            self.mgr.refresh_content()

    def load_idb(self):
        self.mgr.view.wait_dialog.show()
        QApplication.processEvents()
        if idapro.open_database(self.idb_path, True):
            print(f"Failed opening {self.idb_path}")
            sys.exit(1)
        self.mgr.view.wait_dialog.hide()
        self.idle_callback = QTimer()
        self.idle_callback.timeout.connect(self.on_refresh_timer)
        self.idle_callback.start(AppMainWindow.REFRESH_TIME)
        ida_kernwin.request_refresh(ida_kernwin.IWID_SIGNS, True)

    def select_idb(self, idb=env.IDB_PATH):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        # options |= QFileDialog.DontUseNativeDialog
        self.idb_path, _ = QFileDialog.getOpenFileName(self,
                                                       "Open binary file...",
                                                       idb,
                                                       "All Files (*);;IDA Files (*.i64)",
                                                       options=options)

        if not self.idb_path:
            print("Please select a binary file.")
            sys.exit(1)

    def ask_save(self):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Save changes")
        msg_box.setText("Do you want to save your database changes?")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.Yes)
        return msg_box.exec_() == QMessageBox.Yes

    def resize_and_center(self):
        # Get the current cursor position (where the mouse is located)
        cursor_pos = QCursor.pos()

        # Get the screen where the cursor is located
        screen = QApplication.screenAt(cursor_pos)
        screen_geometry = screen.availableGeometry()

        # Calculate the size: 2/3 of the screen width and height
        width = screen_geometry.width() * 2 // 3
        height = screen_geometry.height() * 2 // 3

        # Set the size of the main window
        self.resize(width, height)

        # Calculate the position to center the window on the current screen
        left = screen_geometry.left() + (screen_geometry.width() - width) // 2
        top = screen_geometry.top() + (screen_geometry.height() - height) // 2

        # Move the window to the calculated position
        self.move(left, top)

if __name__ == '__main__':
    SYS_INTERPRETER_PATH = sys.executable
    idapro.enable_console_messages(True)
    app = QApplication(sys.argv)
    QApplication.setStyle(QStyleFactory.create('Fusion'))
    view = AppMainWindow()

    view.select_idb()
    view.load_idb()
    view.mgr.populate_model()
    view.resize_and_center()
    view.show()

    app.exec_()

    save_response = view.ask_save()
    idapro.close_database(save_response)
