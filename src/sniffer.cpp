//
// Created by jimfeng on 23-9-17.
//

#include "sniffer.h"

Sniffer::Sniffer() {
    isListening = false;
    loadDevices();
    setDevice(0); // set default the first device
}

void Sniffer::loadDevices() {
    char errBuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&devices, errBuf) == PCAP_ERROR){
        cerr << "Err: Can not find devices: " << errBuf << endl;
    }
}

void Sniffer::setDevice(int index) {
    pcap_if_t *dev = devices;
    selectedDeviceIndex = index;
    while(dev && (index -- )){
        dev = dev->next;
    }
    currentDevice = dev;
}

int Sniffer::getDevicesInfo(vector<string> &info) {
    pcap_if_t *dev = devices;
    while(dev) {
        if(dev->description == nullptr) {
            info.push_back(dev->name);
        } else {
            info.push_back(dev->description + "(" + dev->name + ")");
        }
        dev = dev->next;
    }
    return 0;
}
