import socket
import re
import struct

protocol_ethernet = {
    b'\x08\x00': "IP",
    b'\x08\x06': "ARP",
    b'\x81\x00': "VLAN",
    b'\x86\xdd': "IPV6",
    b'\x90\x00': "LOOPBACK",
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

arp_h_type = {
    1: "Ethernet"
}

arp_op = {
    1: "arp request",
    2: "arp reply",
    3: "rarp request",
    4: "rarp reply"
}

icmp_type_code = {
    0: {
        0: "Echo (ping) reply"
    },
    3: {
        0: "Network unreachable",
        1: "Host unreachable",
        2: "Protocol unreachable",
        3: "Port unreachable",
        4: "Fragmentation needed and DF set",
        5: "Source route failed"
    },
    5: {
        0: "Redirect for the Network",
        1: "Redirect for the Host",
        2: "Redirect for TOS and Network",
        3: "Redirect for TOS and Host"
    },
    8: {
        0: "Echo (ping) request"
    },
    11: {
        0: "TTL exceeded in transit",
        1: "Fragment reassembly time exceeded"
    },
    12: {
        0: "IP Header parameter error",
        1: "missing necessary option",
        2: "unsupported length"
    },
    13: {
        0: "Timestamp message"
    },
    14: {
        0: "Timestamp reply message"
    }
}

tcp_flags = ["Fin", "Syn", "Rst", "Psh", "Ack", "Urg"]


def check_tcp_flag(flag: str, value: bytes):
    bit = tcp_flags.index(flag)
    return format(ord(value), '08b')[-bit - 1] == "1"


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
            content_len = int(_len.groups()[0])
        _data_cnt.append(end - start + 2)
        start = end + 2
    if len(raw) >= start + content_len:
        words = ["GET", "POST", "HEAD", "PUT", "DELETE", "HTTP"]
        if content_len:
            _data.append(raw[start: start + content_len])
            _data_text.append("Body Data:")
            _data_cnt.append(content_len)
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


def dns_parser(raw: bytes, data, data_cnt, data_text, node_text):

    pass


def icmp_body_parser(raw: bytes, data, data_cnt, data_text, node_text):
    type_code = data[0]
    start = 4
    data_len = 0
    icmp_type, icmp_code = type_code >> 8, type_code & 255
    if icmp_type in [0, 8, 13, 14]:
        ident, seq = struct.unpack("!HH", raw[start:start + 4])
        data += [ident, seq]
        data_cnt += [2, 2]
        data_text += ["Id: {}".format(ident), "Seq: {}".format(seq)]
    # elif icmp_type == 12:
    #
    #     pass
    return data_len, True


FLAG_INFO = 0
FLAG_DST = 1
FLAG_SRC = 2
FLAG_HEADER = 3  # header len byte(next start)
FLAG_LEN = 5  # total len byte (header + body), may produce padding for next level
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
    "ARP": {
        "template": "!H2sBBH6s4s6s4s",
        "len": 28,
        "info": [
            ["Hardware type: {}", lambda x: [arp_h_type.get(x) or ""], 2],
            ["Protocol type: {}", lambda x: [protocol_ethernet.get(x) or ""], 2],
            ["Hardware size: {}", lambda x: [x], 1],
            ["Protocol size: {}", lambda x: [x], 1],
            ["Op: {}", lambda x: [arp_op.get(x) or ""], 2],
            ["Sender MAC: {}", lambda x: [bytes.hex(x, ":")], 6],
            ["Sender IP: {}", lambda x: [socket.inet_ntoa(x)], 4],
            ["Target MAC: {}", lambda x: [bytes.hex(x, ":")], 6],
            ["Target IP: {}", lambda x: [socket.inet_ntoa(x)], 4],
        ]
    },
    "IP": {
        "template": "!BBHHHBBH4s4s",
        "len": 20,
        "info": [
            ["IPv{} Header Len: {} bytes", lambda x: [x // 16, 4 * (x % 16)], 1, (FLAG_HEADER, 1)],
            ["Type of Service: {}", lambda x: [hex(x)], 1],
            ["Total Length: {}", lambda x: [x], 2, (FLAG_LEN, 0)],
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
        "template": "!HH",
        "len": 4,
        "info": [
            ["Type: {} Code: {} {}", lambda x: [x >> 8, x & 255, icmp_type_code.get(x >> 8).get(x & 255)], 2,
             (FLAG_INFO, 2)],
            ["Checksum: {}", lambda x: [hex(x)], 2]
        ],
        "parser": icmp_body_parser
    },
    "TCP": {
        "template": "!HHIIBsHHH",
        "len": 20,
        "info": [
            ["Src port: {}", lambda x: [x], 2, (FLAG_INFO, 0)],
            ["Dst port: {}", lambda x: [x], 2, (FLAG_INFO, 0)],
            ["Seq: {}", lambda x: [x], 4, (FLAG_INFO, 0)],
            ["Ack: {}", lambda x: [x], 4, (FLAG_INFO, 0)],
            ["Header Len: {}", lambda x: [4 * (x >> 4)], 1, (FLAG_HEADER, 0)],
            ["Flag:[{}]",
             lambda x: [",".join(
                 [tcp_flags[i] for i in range(len(tcp_flags)) if (format(ord(x), '08b')[-1 - i] == "1")])], 1],
            ["Window: {}", lambda x: [x], 2],
            ["Checksum: {}", lambda x: [hex(x)], 2],
            ["Urgent Pointer: {}", lambda x: [x], 2]
        ]
    },
    "UDP": {
        "template": "!HHHH",
        "len": 8,
        "info": [
            ["Src port: {}", lambda x: [x], 2, (FLAG_INFO, 0)],
            ["Dst port: {}", lambda x: [x], 2, (FLAG_INFO, 0)],
            ["Length: {}", lambda x: [x], 2, (FLAG_LEN, 0)],
            ["Checksum: {}", lambda x: [hex(x)], 2]
        ]
    },
    "Any": {
        "parsers": [
            (http_parser, ["TCP", ]),
            # (dns_parser, ["UDP", 53])
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

mac_reg = r'([a-f0-9]{2}:){5}[a-f0-9]{2}'

ip_reg = r'((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}'

protocols = ["IP", "ARP", "ICMP", "TCP", "UDP", "HTTP"]
