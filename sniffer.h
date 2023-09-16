//
// Created by jimfeng on 23-9-17.
//

#ifndef JIM_SNIFFER_SNIFFER_H
#define JIM_SNIFFER_SNIFFER_H
#include <pcap.h>

class Sniffer {
public:
    pcap_if_t *devices, *currentDevice;
    bool isListening;
    Sniffer();
    void loadDevices();
};


#endif //JIM_SNIFFER_SNIFFER_H
