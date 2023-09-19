//
// Created by jimfeng on 23-9-17.
//

#include "frame.h"


Frame::Frame(const struct pcap_pkthdr *header, const u_char *data) {
    this->header = new pcap_pkthdr(*header);
    memcpy((char* )raw_data, (char*)data, header->caplen);
}
