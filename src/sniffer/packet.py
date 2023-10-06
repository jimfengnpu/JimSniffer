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
        self.packet_info = {}
        self.dst: list[str] = []
        self.src: list[str] = []
        self.protocol: list[str] = []
        self.protocol_info = []
        self.info: str = ""
        self.data_info.append((index, 0, len(data)))
        Packet.raw_data.append(data)
        self.time = timestamp
        self.start = 0
        self.parse()

    def do_parse(self, protocol, raw, start, reassembled, padding=0):
        next_proto = ""
        data = []
        data_cnt = []
        data_text = []
        node_text = []
        data_len = 0
        _padding = 0
        if protocol and parse_option.get(protocol):
            option = parse_option.get(protocol)
            _data_len = option["len"]
            _data = struct.unpack(option["template"], raw[start:start + _data_len])
            _data_info = [option["info"][i][1](d) for i, d in enumerate(_data)]
            _data_text = [option["info"][i][0].format(*d) for i, d in enumerate(_data_info)]
            node_text.append(protocol)
            for i, op in enumerate(option["info"]):
                if len(op) == 4:
                    (tp, pos) = op[-1]
                    if tp == FLAG_INFO:
                        node_text.append(_data_text[i])
                    elif tp == FLAG_DST:
                        self.dst.append(_data_info[i][pos])
                        node_text.append(_data_text[i])
                    elif tp == FLAG_SRC:
                        self.src.append(_data_info[i][pos])
                        node_text.append(_data_text[i])
                    elif tp == FLAG_LEN:
                        _data_len = _data_info[i][pos]
                        pass
                    elif tp == FLAG_PROTO:
                        next_proto = _data_info[i][pos]
            data += _data
            data_cnt += [info[2] for info in option["info"]]
            data_text += _data_text
            data_len += _data_len
            if option.get("parser"):
                data_len, _ = option["parser"](raw[start:], data, data_cnt, data_text, node_text)
        else:
            match = False
            parsers = parse_option["Any"]["parsers"]
            for parser in parsers:
                data_len, match = parser(raw[start:], data, data_cnt, data_text, node_text)
                if match:
                    break
            if not match:
                return "", start, _padding

        node = PacketProtocolInfo(" ".join(node_text), start, start + data_len, reassembled)
        if len(node_text) < 2:
            print("break")

        self.protocol.append(node_text[0])
        self.packet_info[protocol] = data
        self.protocol_info.append(node)
        self.info = " ".join(node_text[1:])
        self.start = start + data_len + padding
        s = start
        for i, d in enumerate(data_text):
            cnt = data_cnt[i]
            node.addChild(PacketProtocolInfo(data_text[i], s, s + cnt, reassembled))
            s += cnt
        if protocol == "IP":
            _padding = len(raw) - start - data[2]
        # fragment
        if (protocol == "IP" and (data[4] & 0x6000) != 0x4000 and next_proto != "TCP") or protocol == "TCP":
            done = Packet._parse_fragment(self, protocol)
            if not done:
                next_proto = ""
        return next_proto, start + data_len + padding, _padding

    def parse(self, reassembled=False):
        proto = "Ethernet"
        start = 0
        end = 0
        raw = self.get_raw(start, self.get_length(reassembled), reassembled)
        while True:
            _last_start = start
            proto, start, end = self.do_parse(proto, raw, start, reassembled, end)
            if start == _last_start:
                break
        if self.start < self.get_length():
            cnt = self.get_length()
            self.protocol_info[-1].addChild(PacketProtocolInfo("Data:", start, cnt))

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
            res = Packet._get_raw(self.data_info[1:], start, end)
        return res

    @classmethod
    def _get_raw(cls, info, start, end):
        res = b''
        base = 0
        for (index, off, length) in info:
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

    @classmethod
    def _parse_fragment(cls, packet, protocol):
        option = frag_options.get(protocol)  # ensured ip frag or tcp
        info = [packet.packet_info[key][index] for (key, index) in option["match"]]
        seq_option = option["offset"]
        seq_data = packet.packet_info[protocol][seq_option[0]]
        seq = seq_option[1](seq_data)
        seq_nxt = (seq + (packet.get_length() - packet.start)) % (2 ** 32)
        match = False
        packets = []
        syn = 0
        link_id = 0
        for i, pack in enumerate(option["packets"]):
            if pack[1] == info:
                match = True
                packets = pack[0]
                syn = pack[2]
                link_id = i
                break
        if protocol == "TCP" and check_tcp_flag("Syn", packet.packet_info["TCP"][5]):
            if syn:
                print("Error: multiple syn")
            syn = seq
            seq_nxt += 1
        frag_info = (packet, seq, seq_nxt)
        if not match:
            option["packets"].append(([frag_info, ], info, syn))
            return False
        # insert
        packets.append(frag_info)
        packets.sort(key=lambda v: (v[1] - syn + 2 ** 32) % 2 ** 32)
        data_info = []
        last_cont = 0
        info_len = 0
        for i in range(len(packets) - 1):
            if packets[i][2] < packets[i + 1][1]:
                last_cont = i
                break
            if check_tcp_flag("Syn", packets[i][0].packet_info["TCP"][5]):
                length = 0
            else:
                length = min(packets[i + 1][1], packets[i][2]) - packets[i][1]
            info_len += length
            data_info.append((packets[i][0].index, packets[i][0].start, length))
        else:
            last_cont = -1
            length = packets[-1][2] - packets[-1][1]
            info_len += length
            data_info.append((packets[-1][0].index, packets[-1][0].start, length))

        if protocol == "TCP":
            # if TCP try parse
            raw = Packet._get_raw(data_info, 0, info_len)
            _, _start, _pad = packets[last_cont][0].do_parse("", raw, 0, True)
            if _start:
                seg = [str(i[0] + 1) for i in data_info]
                packets[last_cont][0].protocol_info[-2].addChild(
                    PacketProtocolInfo("[Segments: " + ",".join(seg) + "]",
                                       0, info_len, True))
                packets[last_cont][0].data_info += data_info
                packets = packets[last_cont:]
                return False
            if check_tcp_flag("Fin", packet.packet_info["TCP"][5]) \
                    or check_tcp_flag("Rst", packet.packet_info["TCP"][5]):
                option["packets"].pop(link_id)
                if len(data_info) == 1:
                    return True
        else:
            if packets[-1][0].packet_info["IP"][4] & 0x6000 == 0:
                option["packets"].pop(link_id)
        return False
