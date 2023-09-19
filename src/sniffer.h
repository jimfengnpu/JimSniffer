//
// Created by jimfeng on 23-9-17.
//

#ifndef JIM_SNIFFER_SNIFFER_H
#define JIM_SNIFFER_SNIFFER_H
#include <QDebug>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include "frame.h"

using namespace std;

class Sniffer {
    pcap_t *captureAdaptor = nullptr;
    pcap_if_t *devices = nullptr, *currentDevice = nullptr;
    char* tmpDumpFileName = nullptr;
public:
    int deviceCount = 0;
    int currentDeviceIndex = 0;
    bool isListening = false;
    vector<Frame*> frameList;
    Sniffer();
    void loadDevices();
    int getDevicesInfo(vector<string>& info);
    void setDevice(int index);
    void startListening();
    void stopListening();
    void saveCapFile(const string& path);
    void loadCapFile(const string& path);
    static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data);
private:
    void startCapture();

};


#endif //JIM_SNIFFER_SNIFFER_H
