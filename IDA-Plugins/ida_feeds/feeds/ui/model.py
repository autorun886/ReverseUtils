from enum import Enum

from PySide6.QtCore import QDir, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QApplication, QStyle


class SignatureItemState(Enum):
    NONE = (0, 'None')
    VERIFIED = (1, 'Probed')
    APPLIED = (2, 'Applied')

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
    def __init__(self, user_path: str = '', rust_path: str = '', parent=None):
        super(FolderModel, self).__init__(parent)

        self.ROLE_ITEM_PATH = Qt.ItemDataRole.UserRole
        self.ROLE_ITEM_TYPE = Qt.ItemDataRole.UserRole + 1
        self.ITEM_USER_SIGNATURES = 'User Signatures'
        self.ITEM_RUST_SIGNATURES = 'Rust Signatures'
        self.ITEM_RUST_GENERATOR = 'FLIRT for Rust libraries'

        self.user_path = user_path
        self.rust_path = rust_path

        self.folder_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.gear_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_CommandLink)

        self.root_item = None
        self.user_folder_item = None
        self.rust_folder_item = None
        self.rust_generator_item = None

        self.subfolders = None
        self.parent_rust = None
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

        self.rust_folder_item = QStandardItem(self.folder_icon, self.ITEM_RUST_SIGNATURES)
        self.rust_folder_item.setEditable(False)
        self.rust_folder_item.setData(self.ITEM_RUST_SIGNATURES, self.ROLE_ITEM_TYPE)
        self.rust_folder_item.setData(self.rust_path, self.ROLE_ITEM_PATH)
        self.root_item.appendRow(self.rust_folder_item)

        self.rust_generator_item = QStandardItem(self.gear_icon, self.ITEM_RUST_GENERATOR)
        self.rust_generator_item.setEditable(False)
        self.rust_generator_item.setData(self.ITEM_RUST_GENERATOR, self.ROLE_ITEM_TYPE)
        self.root_item.appendRow(self.rust_generator_item)

        self.set_enabled(self.ITEM_RUST_SIGNATURES, False)
        self.set_enabled(self.ITEM_RUST_GENERATOR, False)

    def set_enabled(self, item_type, is_enabled):
        if item_type == self.ITEM_USER_SIGNATURES:
            self.user_folder_item.setEnabled(is_enabled)
            return

        if item_type == self.ITEM_RUST_SIGNATURES:
            self.rust_folder_item.setEnabled(is_enabled)
            return

        if item_type == self.ITEM_RUST_GENERATOR:
            self.rust_generator_item.setEnabled(is_enabled)
            return

    def set_user_path(self, path):
        self.user_path = path
        self.user_folder_item.setData(self.user_path, Qt.ItemDataRole.DisplayRole)
        self._set_path(self.user_path, self.user_folder_item, self.ITEM_USER_SIGNATURES)

    def set_rust_path(self, path):
        self.rust_path = path
        self.rust_folder_item.setData(self.rust_path, Qt.ItemDataRole.DisplayRole)
        # self.set_enabled(self.ITEM_RUST_SIGNATURES, self.rust_path != '')
        self._set_path(self.rust_path, self.rust_folder_item, self.ITEM_RUST_SIGNATURES)

    def _set_path(self, path, item: QStandardItem, item_type):
        item.setData(path, self.ROLE_ITEM_PATH)
        item.setToolTip(path)
        item.removeRows(0, item.rowCount())  # Clear the model
        if path != '':
            self._create_folder_item(path, item, item_type)

    def _create_folder_item(self, path, parent, item_type):
        folder = QDir(path)
        for subfolder in folder.entryInfoList(QDir.Filter.Dirs | QDir.Filter.NoDotAndDotDot):
            if subfolder.isDir():
                child = QStandardItem(self.folder_icon, subfolder.fileName())
                child.setEditable(False)
                child.setData(subfolder.canonicalFilePath(), self.ROLE_ITEM_PATH)
                child.setData(item_type, self.ROLE_ITEM_TYPE)
                parent.appendRow(child)
                self._create_folder_item(subfolder.canonicalFilePath(), child, item_type)
