//
// Created by jimfeng on 23-9-17.
//

#ifndef JIM_SNIFFER_SNIFFER_H
#define JIM_SNIFFER_SNIFFER_H
#include <QDebug>
#include <QObject>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include "frame.h"
#include "packet.h"

using namespace std;

class Sniffer: public QObject{
    pcap_t *captureAdaptor = nullptr;
    pcap_if_t *devices = nullptr, *currentDevice = nullptr;
    char* tmpDumpFileName = nullptr;
    Q_OBJECT
public:
    int deviceCount = 0;
    int currentDeviceIndex = 0;

    bool isListening = false;
    vector<Packet*> packetList;
    explicit Sniffer(QObject* parent = nullptr);
    void loadDevices();
    int getDevicesInfo(vector<string>& info);
    void setDevice(int index);
    void startListening();
    void stopListening();
    void clearFrame();
    void saveCapFile(const string& path);
    void loadCapFile(const string& path);
    static void packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data);
    signals:
    void onPacketReceive(Packet* packet);
private:
    void startCapture();

};

extern Sniffer* instance;
extern int packetCount;
#endif //JIM_SNIFFER_SNIFFER_H
