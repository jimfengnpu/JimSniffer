from PyQt5.QtWidgets import QLineEdit
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import Qt, pyqtSignal


class FilterEdit(QLineEdit):
    val_color = Qt.darkGreen
    fail_color = Qt.red
    filter_changed: pyqtSignal = pyqtSignal()

    def __init__(self, parent, checker):
        super().__init__(parent=parent)
        self.setFixedHeight(35)
        self.checker = checker
        self.valid = True
        self.textChanged.connect(self.on_check)

    def on_check(self):
        s = self.text()
        val = True
        old_val = self.valid
        if self.checker:
            val = self.checker(s)
        if val != old_val:
            color = FilterEdit.val_color if val else FilterEdit.fail_color
            palette = QPalette()
            palette.setColor(QPalette.Text, color)
            palette.setColor(QPalette.PlaceholderText, Qt.gray)
            self.setPalette(palette)

        self.valid = val
        if old_val != val or val:
            self.filter_changed.emit()

    def match(self, candidates):
        s = self.text()
        if not self.valid or not s:
            return True
        return s in candidates or s.upper() in candidates
