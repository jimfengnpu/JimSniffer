import socket


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

FLAG_INFO = 0
FLAG_DST = 1
FLAG_SRC = 2
FLAG_LEN = 3
FLAG_FRAG = 4
FLAG_PROTO = 5

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
            ["IPv{} Header Len: {} bytes", lambda x: [x // 16, 4 * (x % 16)], 1],
            ["Type of Service: {}", lambda x: [hex(x)], 1],
            ["Total Length: {}", lambda x: [x], 2],
            ["Identification: {}", lambda x: [hex(x)], 2],
            ["Flag: {} Offset: {}", lambda x: [ip_frag_flag.get(x & 0x6000) or "", x & 0x1ff], 2],
            ["Time to Live: {}", lambda x: [x], 1],
            ["Protocol: {}", lambda x: [protocol_ip.get(x) or ""], 1, (FLAG_PROTO, 0)],
            ["Header Checksum: {}", lambda x: [hex(x)], 2],
            ["Src Addr: {}", lambda x: [socket.inet_ntoa(x)], 4, (FLAG_SRC, 0)],
            ["Dst Addr: {}", lambda x: [socket.inet_ntoa(x)], 4, (FLAG_DST, 0)]
        ]
    }
}
