import threading

import libpcap as pcap
import sys
from shutil import copyfile
import ctypes as ct

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt, QVariant

from .packet import Packet

# lib_name = "npcap"  #  npcap | wpcap | tcpdump | lib abs path
lib_name = None  # default auto (by path env)
pcap.config(LIBPCAP=lib_name)
err_buf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)


class Sniffer(QAbstractTableModel):

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        # self.table: QTableView = table
        self._capture_adaptor = None
        self._devices = ct.POINTER(pcap.pcap_if_t)()
        self._current_device = ct.POINTER(pcap.pcap_if_t)()
        self._tmp_dump_file = ""
        self._dumper = None
        self._t_capture = None
        self.device_cnt = 0
        self.current_device_index = 0
        self.is_listening = False
        self.is_file = False
        self.packet_list: list[Packet] = []
        self.header = [
            "No.", "Src", "Dst", "Protocol", "Length", "Info"
        ]

    def load_devices(self):
        pcap.findalldevs(ct.byref(self._devices), err_buf)
        if err_buf.value:
            print("error: find devices", err_buf.value, file=sys.stderr)
        num = 0
        _dev = self._devices
        while _dev:
            _dev = _dev.contents.next
            num += 1
        self.device_cnt = num

    def set_device(self, index):
        if index >= self.device_cnt:
            return
        _dev = self._devices
        while _dev and index:
            index -= 1
            _dev = _dev.contents.next
        self._current_device = _dev

    def get_devices_info(self):
        info = []
        _dev = self._devices
        while _dev:
            info.append(str(_dev.contents.name, encoding='utf-8'))
            _dev = _dev.contents.next
        return info

    def start_listening(self):  # called when start realtime capture
        self._capture_adaptor = pcap.open_live(self._current_device.contents.name, 65536, 1, 1000, err_buf)
        if err_buf.value:
            print("open failed:", err_buf.value, file=sys.stderr)
            return
        link_type = pcap.datalink(self._capture_adaptor)
        if link_type != 1:
            print("Warning: Non-Ethernet interface detected, Link type:",
                  pcap.datalink_val_to_description_or_dlt(link_type).decode('utf-8'))
        self._tmp_dump_file = "/tmp/cap_temp.cap"  # filename for temp file
        self.is_listening = True
        self.is_file = False
        self.start_capture()

    def stop_listening(self):
        self.is_listening = False
        pcap.breakloop(self._capture_adaptor)
        self._t_capture.join()

    #  common interface for capture and load cap file
    def start_capture(self):
        if self._tmp_dump_file:
            self._dumper = pcap.dump_open(self._capture_adaptor,
                                          ct.c_char_p(self._tmp_dump_file.encode('utf-8')))
        self._t_capture = threading.Thread(target=self.capture_run)
        self._t_capture.start()

    def capture_run(self):
        dumper = None  # dumper will pass as user
        if self._dumper:
            dumper = ct.cast(self._dumper, ct.POINTER(ct.c_ubyte))
        print("start capture...")
        pcap.loop(self._capture_adaptor, ct.c_int(0), pcap.pcap_handler(self.packet_handler), dumper)
        pcap.close(self._capture_adaptor)
        if dumper:
            pcap.dump_flush(self._dumper)
            pcap.dump_close(self._dumper)

    def packet_handler(self, user, header, data):
        if user:
            pcap.dump(user, header, data)
        packet = Packet(len(self.packet_list), bytes(ct.pointer(data.contents)[:header.contents.caplen]),
                        header.contents.ts.tv_sec)  # create and parse packet data
        r = self.rowCount()
        self.beginInsertRows(QModelIndex(), r, r)  # update model data and tell ui to update
        self.packet_list.append(packet)
        self.endInsertRows()

    def load_cap(self, path):
        self._capture_adaptor = pcap.open_offline(ct.c_char_p(path.encode()), err_buf)
        if err_buf.value:
            print("error: open cap file:", path, err_buf.value, file=sys.stderr)
            return
        self.is_file = True
        self.start_capture()

    def save_cap(self, path):
        if not self._tmp_dump_file:
            return
        print("save file: ", self._tmp_dump_file, ">>", path)
        copyfile(self._tmp_dump_file, path)

    def clear(self):
        if self.is_listening:
            return  # protect prog
        # self.table.clear()
        self.beginResetModel()
        self.packet_list.clear()
        Packet.raw_data.clear()
        self.endResetModel()

    def data(self, index: QModelIndex, role: int = ...):  # called everytime ui update to get new content
        if role == Qt.DisplayRole:
            row = index.row()
            col = index.column()
            packet: Packet = self.packet_list[row]
            return packet.get_info(col)
        return QVariant()

    def rowCount(self, parent: QModelIndex = ...) -> int:
        return len(self.packet_list)

    def columnCount(self, parent: QModelIndex = ...) -> int:
        return 6

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = ...):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.header[section]
        return QVariant()
