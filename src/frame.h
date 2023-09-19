//
// Created by jimfeng on 23-9-17.
//

#ifndef JIM_SNIFFER_FRAME_H
#define JIM_SNIFFER_FRAME_H
#include <pcap.h>
#include <cstring>

#define MAX_FRAME_LEN 65536

class Frame{
public:
    struct pcap_pkthdr *header;
    u_char raw_data[MAX_FRAME_LEN]{};
    Frame(const struct pcap_pkthdr* header, const u_char* data);
};


#endif //JIM_SNIFFER_FRAME_H
