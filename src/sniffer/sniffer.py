import threading

import libpcap as pcap
import platform
import sys
from shutil import copyfile
import ctypes as ct

from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem

from .packet import Packet

lib_name = "wpcap" if (platform.system() == "Windows") else "tcpdump"
pcap.config(LIBPCAP=lib_name)
err_buf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)


# noinspection PyTypeChecker
class Sniffer:

    def __init__(self, table):
        super().__init__()
        self.table: QTableWidget = table
        self._capture_adaptor = None
        self._devices = ct.POINTER(pcap.pcap_if_t)()
        self._current_device = ct.POINTER(pcap.pcap_if_t)()
        self._tmp_dump_file = ""
        self._dumper = None
        self._t_capture = None
        self.device_cnt = 0
        self.current_device_index = 0
        self.is_listening = False
        self.packet_list = []

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

    def start_listening(self):
        self._capture_adaptor = pcap.open_live(self._current_device.contents.name, 65536, 1, 1000, err_buf)
        if err_buf.value:
            print("open failed:", err_buf.value, file=sys.stderr)
            return
        link_type = pcap.datalink(self._capture_adaptor)
        if link_type != 1:
            print("Warning: Non-Ethernet interface detected, Link type:",
                  pcap.datalink_val_to_description_or_dlt(link_type).decode('utf-8'))
        self._tmp_dump_file = "/tmp/cap_temp.cap"
        self.is_listening = True
        self.start_capture()

    def stop_listening(self):
        self.is_listening = False
        pcap.breakloop(self._capture_adaptor)
        self._t_capture.join()

    def start_capture(self):
        if self._tmp_dump_file:
            self._dumper = pcap.dump_open(self._capture_adaptor,
                                          ct.c_char_p(self._tmp_dump_file.encode('utf-8')))
        self._t_capture = threading.Thread(target=self.capture_run)
        self._t_capture.start()

    def capture_run(self):
        dumper = None
        if self._dumper:
            dumper = ct.cast(self._dumper, ct.POINTER(ct.c_ubyte))
        print("running")
        pcap.loop(self._capture_adaptor, ct.c_int(0), pcap.pcap_handler(self.packet_handler), dumper)
        pcap.close(self._capture_adaptor)
        if dumper:
            pcap.dump_flush(self._dumper)
            pcap.dump_close(self._dumper)

    def packet_handler(self, user, header, data):
        if user:
            pcap.dump(user, header, data)
        packet = Packet(len(self.packet_list), bytes(ct.pointer(data.contents)[:header.contents.caplen]),
                        header.contents.ts.tv_sec)
        self.packet_list.append(packet)
        # print(packet.time, packet.data[0])
        r = self.table.rowCount()
        self.table.insertRow(r)
        for c, i in enumerate(packet.get_info()):
            self.table.setItem(r, c, QTableWidgetItem(i))

    def load_cap(self, path):
        self._capture_adaptor = pcap.open_offline(ct.c_char_p(path.encode()), err_buf)
        if err_buf.value:
            print("error: open cap file:", path, err_buf.value, file=sys.stderr)
            return
        self.start_capture()

    def save_cap(self, path):
        print("save file: ", self._tmp_dump_file, ">>", path)
        copyfile(self._tmp_dump_file, path)

    def clear(self):
        if self.is_listening:
            return  # protect prog
        self.table.clear()
        self.packet_list.clear()

