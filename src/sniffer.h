//
// Created by jimfeng on 23-9-17.
//

#ifndef JIM_SNIFFER_SNIFFER_H
#define JIM_SNIFFER_SNIFFER_H
#include <pcap.h>
#include <iostream>
#include <vector>

using namespace std;

class Sniffer {
    pcap_t *captureData;
    pcap_if_t *devices, *currentDevice;
public:
    int deviceCount;
    int currentDeviceIndex;
    bool isListening;
    Sniffer();
    void loadDevices();
    int getDevicesInfo(vector<string>& info);
    void setDevice(int index);
};


#endif //JIM_SNIFFER_SNIFFER_H
