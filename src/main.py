from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import QTreeWidgetItem

from sniffer import *
import sys

SRC_COLUMN = 1
DST_COLUMN = 2


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
        self.sniffer = Sniffer(self.packetView)
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
        self.packetView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packetView.setShowGrid(False)
        self.packetView.setColumnCount(6)
        self.packetView.setHorizontalHeaderLabels([
            "No.", "Src", "Dst", "Protocol", "Length", "Info"
        ])
        self.packetView.horizontalHeader().setDefaultSectionSize(80)
        self.packetView.verticalHeader().setVisible(False)
        self.packetView.setColumnWidth(SRC_COLUMN, 160)
        self.packetView.setColumnWidth(DST_COLUMN, 160)
        self.packetView.horizontalHeader().setStretchLastSection(True)
        self.protocolView.header().setVisible(False)
        self.protocolView.setSelectionMode(QAbstractItemView.SingleSelection)
        self.set_controller()
        self.update_devices()
        self.update_state()
        self.show()

    def update_devices(self):
        self.devSelector.clear()
        self.sniffer.load_devices()
        self.sniffer.set_device(0)
        infos = self.sniffer.get_devices_info()
        for info in infos:
            self.devSelector.addItem(info)

    def update_state(self):
        listening = self.sniffer.is_listening
        self.startBtn.setDisabled(listening)
        self.devSelector.setDisabled(listening)
        self.endBtn.setEnabled(listening)

    def set_controller(self):
        self.devSelector.currentIndexChanged.connect(self.sniffer.set_device)
        self.startBtn.clicked.connect(lambda: (self.sniffer.start_listening(), self.update_state()))
        self.endBtn.clicked.connect(lambda: (self.sniffer.stop_listening(), self.update_state()))
        self.packetView.cellClicked.connect(lambda r, c: self.on_packet_selected(r))
        self.protocolView.itemSelectionChanged.connect(lambda: self.on_info_selected())

    def on_packet_selected(self, index):
        if index >= len(self.sniffer.packet_list):
            return
        _packet: Packet = self.sniffer.packet_list[index]
        self.selectedPacket = _packet
        while self.protocolView.topLevelItemCount():
            self.protocolView.takeTopLevelItem(0)
        for item in _packet.protocol_info:
            self.protocolView.addTopLevelItem(item)
        self.protocolView.expandAll()
        self.hexDataView.setText(_packet.get_hex(0, _packet.get_length()))

    def on_info_selected(self):
        items: list[QTreeWidgetItem] = self.protocolView.selectedItems()
        if len(items) < 1:
            return
        info: PacketProtocolInfo = items[0]
        _packet: Packet = self.selectedPacket
        self.hexDataView.setText(
            _packet.get_hex(0, _packet.get_length(info.reassembled), info.reassembled))
        cursor = self.hexDataView.textCursor()
        cursor.clearSelection()
        cursor.setPosition(info.start * 3)
        cursor.setPosition(info.end * 3 - 1, QTextCursor.KeepAnchor)
        self.hexDataView.setTextCursor(cursor)
        pass


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = Main()
    sys.exit(app.exec_())
