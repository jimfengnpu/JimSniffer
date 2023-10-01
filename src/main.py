from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, \
    QVBoxLayout, QHBoxLayout, QMenuBar, QToolBar, QComboBox, QPushButton, \
    QTableWidget, QTreeWidget, QTextEdit, QAbstractItemView
from PyQt5.QtGui import QFont
import sys


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Jim Sniffer")
        self.setGeometry(300, 300, 1000, 700)
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        v_layout = QVBoxLayout(central_widget)
        self.menu = QMenuBar(self)
        self.setMenuBar(self.menu)
        self.toolBar = QToolBar(self)
        self.addToolBar(self.toolBar)
        self.devSelector = QComboBox(self)
        self.startBtn = QPushButton(text="开始")
        self.endBtn = QPushButton(text="结束")
        self.packetView = QTableWidget(self)
        self.protocolView = QTreeWidget(self)
        self.hexDataView = QTextEdit(self)

        dock_layout = QHBoxLayout()
        v_layout.addWidget(self.packetView)
        v_layout.addLayout(dock_layout)
        self.toolBar.addWidget(self.devSelector)
        self.toolBar.addWidget(self.startBtn)
        self.toolBar.addWidget(self.endBtn)
        self.devSelector.resize(200, 40)
        self.packetView.resize(1000, 300)
        dock_layout.addWidget(self.protocolView)
        dock_layout.addWidget(self.hexDataView)
        self.protocolView.resize(500, 300)
        self.hexDataView.resize(500, 300)
        self.hexDataView.setReadOnly(True)
        self.hexDataView.setFont(QFont("Noto Mono", 12))
        self.selectedPacket = None
        self.packetView.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packetView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = Main()
    sys.exit(app.exec_())
