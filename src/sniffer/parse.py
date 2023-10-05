import socket
import re

protocol_ethernet = {
    b'\x08\x00': "IP",
    b'\x08\x06': "ARP"
}

protocol_ip = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
}

ip_frag_flag = {
    0x4000: "Don't Fragment",
    0x2000: "More Fragment",
    0: "No more Fragment"
}

tcp_flags = ["Fin", "Syn", "Rst", "Psh", "Ack", "Urg"]


def check_tcp_flag(flag: str, value: bytes):
    bit = tcp_flags.index(flag)
    return format(ord(value), '08b')[-bit-1] == "1"


def http_parser(raw: bytes, data, data_cnt, data_text, node_text):
    content_len = 0
    match = False
    start = 0
    _data = []
    _data_cnt = []
    _data_text = []
    _node_text = ["HTTP"]
    while True:
        end = raw.find(b'\x0d\x0a', start)
        if end == -1:
            break
        info = raw[start:end]
        _data.append(info)
        text = str(info)[2:-1]
        _data_text.append(text)
        _len = re.match(r'[Cc]ontent-[Ll]ength: (\d+)', text)
        if _len:
            content_len = _len.groups()[0]
        _data_cnt.append(end - start + 2)
        start = end + 2
    if len(raw) >= start + content_len:
        words = ["GET", "POST", "HEAD", "PUT", "DELETE", "HTTP"]
        for w in words:
            if raw.find(w.encode('utf8')) == 0:
                match = True
    if match:
        _node_text.append(_data_text[0])
        data += _data
        data_cnt += _data_cnt
        data_text += _data_text
        node_text += _node_text
    return start + content_len, match


FLAG_INFO = 0
FLAG_DST = 1
FLAG_SRC = 2
FLAG_LEN = 3
FLAG_PROTO = 4

parse_option = {
    "Ethernet": {
        "template": "!6s6s2s",
        "len": 14,
        "info": [
            # lambda item: list[printable(str/int)], len == {}.cnt in prompt,
            # optional index -1: update %flagItem[%0] with list[%1]
            # info/dst/src/len/frag/next [0...5]
            ["Dst: {}", lambda x: [bytes.hex(x, ":")], 6, (FLAG_DST, 0)],
            ["Src: {}", lambda x: [bytes.hex(x, ":")], 6, (FLAG_SRC, 0)],
            ["Protocol: {}", lambda x: [protocol_ethernet.get(x) or ""], 2, (FLAG_PROTO, 0)]
        ]
    },
    "IP": {
        "template": "!BBHHHBBH4s4s",
        "len": 20,
        "info": [
            ["IPv{} Header Len: {} bytes", lambda x: [x // 16, 4 * (x % 16)], 1, (FLAG_LEN, 1)],
            ["Type of Service: {}", lambda x: [hex(x)], 1],
            ["Total Length: {}", lambda x: [x], 2],
            ["Identification: {}", lambda x: [hex(x)], 2],
            ["Flag: {} Offset: {}", lambda x: [ip_frag_flag.get(x & 0x6000) or "", 8 * (x & 0x1ff)], 2],
            ["Time to Live: {}", lambda x: [x], 1],
            ["Protocol: {}", lambda x: [protocol_ip.get(x) or ""], 1, (FLAG_PROTO, 0)],
            ["Header Checksum: {}", lambda x: [hex(x)], 2],
            ["Src addr: {}", lambda x: [socket.inet_ntoa(x)], 4, (FLAG_SRC, 0)],
            ["Dst addr: {}", lambda x: [socket.inet_ntoa(x)], 4, (FLAG_DST, 0)]
        ]
    },
    "ICMP": {

    },
    "TCP": {
        "template": "!HHIIBsHHH",
        "len": 20,
        "info": [
            ["Src port: {}", lambda x: [x], 2, (FLAG_INFO, 0)],
            ["Dst port: {}", lambda x: [x], 2, (FLAG_INFO, 0)],
            ["Seq: {}", lambda x: [x], 4, (FLAG_INFO, 0)],
            ["Ack: {}", lambda x: [x], 4, (FLAG_INFO, 0)],
            ["Header Len: {}", lambda x: [4 * (x >> 4)], 1, (FLAG_LEN, 0)],
            ["Flag:[{}]",
             lambda x: [",".join(
                 [tcp_flags[i] for i in range(len(tcp_flags)) if (format(ord(x), '08b')[-1-i] == "1")])], 1],
            ["Window: {}", lambda x: [x], 2],
            ["Checksum: {}", lambda x: [hex(x)], 2],
            ["Urgent Pointer: {}", lambda x: [x], 2]
        ]
    },
    "Any": {
        "parsers": [
            http_parser
        ]
    }
}

frag_options = {
    "IP": {
        "match": [("IP", 3), ("IP", -2), ("IP", -1), ("IP", -4)],
        "offset": (4, lambda x: 8 * (x & 0x1ff)),
        "packets": []
    },
    "TCP": {
        "match": [("IP", -2), ("IP", -1), ("TCP", 0), ("TCP", 1)],
        "offset": (2, lambda x: x),
        "packets": []
    }
}
