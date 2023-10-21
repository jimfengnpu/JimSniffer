from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtGui import QColor


class FilterEdit(QTextEdit):
    val_color = QColor("green")
    fail_color = QColor("red")

    def __init__(self, parent, checker):
        super().__init__(self, parent)
        self.checker = checker
        self.valid = True
        self.textChanged.connect(self.on_check)

    def on_check(self):
        s = self.toPlainText()
        val = True
        if self.checker:
            val = self.checker(s)
        self.valid = val
        if val:
            self.setTextColor(FilterEdit.val_color)
        else:
            self.setTextColor(FilterEdit.fail_color)
