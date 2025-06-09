from enum import Enum
from PyQt5.QtCore import Qt, QDir
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QStyle, QApplication


class SignatureItemState(Enum):
    NONE = (0, "None")
    VERIFIED = (1, "Probed")
    APPLIED = (2, "Applied")

    @property
    def value_int(self):
        return self.value[0]

    @property
    def description(self):
        return self.value[1]

    @classmethod
    def from_value(cls, value):
        for member in cls:
            if member.value_int == value:
                return member
        return cls.NONE

class FolderModel(QStandardItemModel):
    def __init__(self, user_path:str='', parent=None):
        super(FolderModel, self).__init__(parent)

        self.ROLE_ITEM_PATH = Qt.UserRole
        self.ROLE_ITEM_TYPE = Qt.UserRole + 1
        self.ITEM_USER_SIGNATURES = "User Signatures"

        self.user_path = user_path

        self.folder_icon = QApplication.style().standardIcon(QStyle.SP_DirIcon)
        self.file_icon = QApplication.style().standardIcon(QStyle.SP_FileIcon)

        self.root_item = None
        self.user_folder_item = None

        self.subfolders = None
        self.parent_sigs = None

        self._prepare()

    def _prepare(self):
        self.root_item = self.invisibleRootItem()

        self.user_folder_item = QStandardItem(self.folder_icon, self.user_path)
        self.user_folder_item.setEditable(False)
        self.user_folder_item.setData(self.ITEM_USER_SIGNATURES, self.ROLE_ITEM_TYPE)
        self.user_folder_item.setData(self.user_path, self.ROLE_ITEM_PATH)
        self.user_folder_item.setToolTip(self.user_path)
        self.root_item.appendRow(self.user_folder_item)

    def set_enabled(self, item_type, is_enabled):
        if item_type == self.ITEM_USER_SIGNATURES:
            self.user_folder_item.setEnabled(is_enabled)
            return

    def set_user_path(self, path):
        self.user_path = path
        self.user_folder_item.setData(self.user_path, Qt.DisplayRole)
        self._set_path(self.user_path, self.user_folder_item, self.ITEM_USER_SIGNATURES)

    def _set_path(self, path, item:QStandardItem, item_type):
        item.setData(path, self.ROLE_ITEM_PATH)
        item.setToolTip(path)
        item.removeRows(0, item.rowCount())  # Clear the model
        if path != '':
            self._create_folder_item(path, item, item_type)

    def _create_folder_item(self, path, parent, item_type):
        folder = QDir(path)
        for subfolder in folder.entryInfoList(QDir.Dirs | QDir.NoDotAndDotDot):
            if subfolder.isDir():
                child = QStandardItem(self.folder_icon, subfolder.fileName())
                child.setEditable(False)
                child.setData(subfolder.canonicalFilePath(), self.ROLE_ITEM_PATH)
                child.setData(item_type, self.ROLE_ITEM_TYPE)
                parent.appendRow(child)
                self._create_folder_item(subfolder.canonicalFilePath(), child, item_type)
