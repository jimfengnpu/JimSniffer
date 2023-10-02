import struct

from PyQt5.QtWidgets import QTreeWidgetItem
from .parse import *


class PacketProtocolInfo(QTreeWidgetItem):
    def __init__(self, info: str, start, end, reassembled=False):
        super().__init__()
        self.info = info
        self.start = start
        self.end = end
        self.reassembled = reassembled
        self.setText(0, info)


class Packet:
    raw_data = []

    def __init__(self, index, data: bytes, timestamp):
        self.index = index
        self.data_info = []
        self.packet_info = []
        self.dst: list[str] = []
        self.src: list[str] = []
        self.protocol: list[str] = []
        self.protocol_info = []
        self.info: str = ""
        self.data_info.append((index, 0, len(data)))
        Packet.raw_data.append(data)
        self.time = timestamp
        self.parse()

    def _parse(self, protocol, start, reassembled):
        next_proto = ""
        option = parse_option.get(protocol)
        if not option:
            return next_proto, start, reassembled
        data_len = option["len"]
        raw = self.get_raw(start, start + data_len, reassembled)
        data = struct.unpack(option["template"], raw)
        data_info = [option["info"][i][1](d) for i, d in enumerate(data)]
        data_text = [option["info"][i][0].format(*d) for i, d in enumerate(data_info)]
        node_text = [protocol]
        for i, op in enumerate(option["info"]):
            if len(op) == 4:
                (tp, pos) = op[-1]
                if tp == FLAG_INFO:
                    node_text.append(data_text[i])
                elif tp == FLAG_DST:
                    self.dst.append(data_info[i][pos])
                    node_text.append(data_text[i])
                elif tp == FLAG_SRC:
                    self.src.append(data_info[i][pos])
                    node_text.append(data_text[i])
                elif tp == FLAG_LEN:
                    pass
                elif tp == FLAG_PROTO:
                    next_proto = data_info[i][pos]

        node = PacketProtocolInfo(" ".join(node_text), start, start + data_len, reassembled)
        self.packet_info.append(data_info)
        self.protocol_info.append(node)
        self.info = " ".join(node_text[1:])
        s = start
        for i, d in enumerate(data_info):
            cnt = option["info"][i][2]
            node.addChild(PacketProtocolInfo(data_text[i], s, s + cnt, reassembled))
            s += cnt
        return next_proto, start + data_len, reassembled

    def parse(self):
        proto = "Ethernet"
        start = 0
        reassembled = False
        while proto:
            proto, start, reassembled = self._parse(proto, start, reassembled)
            if proto:
                self.protocol.append(proto)

    def get_info(self):
        return [
            str(self.index + 1),
            self.src[-1] if len(self.src) else "",
            self.dst[-1] if len(self.dst) else "",
            self.protocol[-1] if len(self.protocol) else "",
            str(self.data_info[0][2]),
            self.info
        ]

    def get_hex(self, start, end, reassembled=False):
        return self.get_raw(start, end, reassembled).hex(" ")

    def get_raw(self, start, end, reassembled=False) -> bytes:
        if not reassembled:
            return Packet.raw_data[self.index][start:end]
        res = b''
        if len(self.data_info) > 1:
            base = 0
            for (index, off, length) in self.data_info[1:]:
                if base >= end:
                    break
                if base + length > start:
                    seg = max(0, start - base)
                    bound = min(end - base, length)
                    res += Packet.raw_data[index][seg + off:bound + off]
        return res

    def get_length(self, reassembled=False):
        if not reassembled:
            return self.data_info[0][2]
        tot_length = 0
        for (index, off, length) in self.data_info[1:]:
            tot_length += length
        return tot_length
