import os
import re

from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import QTreeWidgetItem

from sniffer import *
from sniffer.filter_edit import FilterEdit
from sniffer.parse import mac_reg, ip_reg, protocols
import sys

SRC_COLUMN = 1
DST_COLUMN = 2


class Main(QMainWindow):
    def __init__(self):
        super().__init__(parent=None)
        self.setWindowTitle("Jim Sniffer")
        self.setGeometry(300, 300, 1000, 700)
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        v_layout = QVBoxLayout(central_widget)
        self.menu = QMenuBar(self)
        self.setMenuBar(self.menu)
        self.file_menu = self.menu.addMenu("&File")
        self.toolBar = QToolBar(self)
        self.addToolBar(self.toolBar)
        self.devSelector = QComboBox(self)
        self.startBtn = QPushButton(text="开始")
        self.endBtn = QPushButton(text="结束")
        self.src_filter = FilterEdit(None,
                                     lambda txt:
                                     bool(re.match(mac_reg, txt))
                                     or bool(re.match(ip_reg, txt)))
        self.src_filter.setPlaceholderText("Src")
        self.dst_filter = FilterEdit(None,
                                     lambda txt:
                                     bool(re.match(mac_reg, txt))
                                     or bool(re.match(ip_reg, txt)))
        self.dst_filter.setPlaceholderText("Dst")
        self.proto_filter = FilterEdit(None, lambda txt: txt.upper() in protocols)
        self.proto_filter.setPlaceholderText("Protocol")
        # self.packetView = QTableWidget(self)
        self.packetView = QTableView(self)
        self.protocolView = QTreeWidget(self)
        self.hexDataView = QTextEdit(self)
        self.sniffer = Sniffer(self.packetView)
        dock_layout = QHBoxLayout()
        v_layout.addWidget(self.packetView)
        v_layout.addLayout(dock_layout)
        self.toolBar.addWidget(self.devSelector)
        self.toolBar.addWidget(self.startBtn)
        self.toolBar.addWidget(self.endBtn)
        self.toolBar.addWidget(self.src_filter)
        self.toolBar.addWidget(self.dst_filter)
        self.toolBar.addWidget(self.proto_filter)
        self.devSelector.resize(200, 40)
        self.packetView.resize(1000, 300)
        dock_layout.addWidget(self.protocolView)
        dock_layout.addWidget(self.hexDataView)
        self.protocolView.resize(500, 300)
        self.hexDataView.resize(500, 300)
        self.hexDataView.setReadOnly(True)
        self.hexDataView.setFont(QFont("Noto Mono", 12))
        self.selectedPacket = None
        self.packetView.setModel(self.sniffer)
        self.packetView.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packetView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packetView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packetView.setShowGrid(False)
        self.packetView.horizontalHeader().setDefaultSectionSize(80)
        self.packetView.verticalHeader().setVisible(False)
        self.packetView.setColumnWidth(SRC_COLUMN, 160)
        self.packetView.setColumnWidth(DST_COLUMN, 160)
        self.packetView.horizontalHeader().setStretchLastSection(True)
        self.protocolView.header().setVisible(False)
        self.protocolView.setSelectionMode(QAbstractItemView.SingleSelection)
        self.set_menu()
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
        self.file_menu.setDisabled(listening)
        self.endBtn.setEnabled(listening)

    def set_controller(self):
        self.devSelector.currentIndexChanged.connect(self.sniffer.set_device)
        self.startBtn.clicked.connect(self.on_action_start)
        self.endBtn.clicked.connect(self.on_action_stop)
        self.packetView.selectionModel().currentChanged.connect(lambda cur, prev: self.on_packet_selected(cur.row()))
        self.protocolView.itemSelectionChanged.connect(lambda: self.on_info_selected())
        self.packetView.model().rowsInserted.connect(lambda parent, first, last: self.on_filter_apply(first))
        self.src_filter.filter_changed.connect(self.on_filter_apply)
        self.dst_filter.filter_changed.connect(self.on_filter_apply)
        self.proto_filter.filter_changed.connect(self.on_filter_apply)

    def set_menu(self):
        save_file_action = QAction("Save File", self)
        save_file_action.triggered.connect(self.on_action_save)
        self.file_menu.addAction(save_file_action)
        load_file_action = QAction("Load File", self)
        load_file_action.triggered.connect(self.on_action_load)
        self.file_menu.addAction(load_file_action)

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

    def on_action_save(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "保存文件", os.getcwd(), "Pcap dump File(*.pcap)")
        if file_name:
            self.sniffer.save_cap(file_name)

    def on_action_load(self):
        if not self.sniffer.is_file and self.sniffer.rowCount():
            if not self.check_confirm():
                return
        file_name, _ = QFileDialog.getOpenFileName(self, "载入文件", os.getcwd(), "Pcap dump File(*.pcap)")
        if file_name:
            self.sniffer.clear()
            self.sniffer.load_cap(file_name)

    def on_action_start(self):
        if not self.sniffer.is_file and self.sniffer.rowCount():
            if not self.check_confirm():
                return
        self.sniffer.clear()
        self.sniffer.start_listening()
        self.update_state()

    def on_action_stop(self):
        self.sniffer.stop_listening()
        self.update_state()

    def check_confirm(self):
        res = QMessageBox.question(self, "提示", "是否保存已有数据包？\nSave 保存, Discard 不保存,继续, Cancel 取消",
                                   QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
        if res == QMessageBox.Cancel:
            return False
        elif res == QMessageBox.Save:
            self.on_action_save()
        return True

    def on_filter_apply(self, start=0):
        for i in range(start, self.sniffer.rowCount()):
            _packet: Packet = self.sniffer.packet_list[i]
            match = True
            match = match and self.proto_filter.match(_packet.protocol)
            match = match and self.src_filter.match(_packet.src)
            match = match and self.dst_filter.match(_packet.dst)
            self.packetView.setRowHidden(i, not match)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = Main()
    sys.exit(app.exec_())
