//
// Created by jimfeng on 23-9-18.
//

#ifndef JIM_SNIFFER_PACKET_H
#define JIM_SNIFFER_PACKET_H
#include <QTreeWidgetItem>
#include <QListWidgetItem>
#include <sstream>
#include <list>
#include <iostream>
#include <iomanip>
#include "frame.h"

#ifdef __linux__
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32

#endif

using namespace std;

class PacketInfo: public QTreeWidgetItem{
public:
    string key;
    bool reassembled;
    int start;
    int end;
    PacketInfo(const std::string& info, int start, int end, string key, bool reassembled = false);
    int addSubInfo(const string& info, int s, int len, string infoKey="");
};

typedef struct {
    u_char *start;
    int len;
} PacketDataInfo;

class Packet {
public:
    int frameId;
    string src;
    string dst;
    string proto;
    string info;
    Frame *frame;
    iphdr *ipHdr = nullptr;
    int ipFragFlag = 0;
    int ipFragOff = 0;
    int length;
    int parsedLength;
    vector<PacketDataInfo> data;

    // normal first:Frame data, other: reassembled data
    vector<PacketInfo*> protocolInfo;
    explicit Packet(int id, Frame *frame);
    string getData(bool reassembled = false);
    bool getReassembledRaw(uchar* dstData, int len, int offset = 0);
    int getReassembledLength();
    bool setIPFragmentDone();
    void parse();
    void parseIP(u_char *start, int baseOffset);
    void parseTCP(u_char *start, int baseOffset);
    void parseUDP(u_char *start, int baseOffset);
    void parseICMP(u_char *start, int baseOffset);
    void parseHTTP(u_char *start, int baseOffset);
    void parseARP(u_char *start, int baseOffset);
};

struct IPFragmentInfo{
    Packet *packet;
    friend bool operator == (const IPFragmentInfo& a, const IPFragmentInfo& b){
        auto ipA = a.packet->ipHdr;
        auto ipB = b.packet->ipHdr;
        return (ipA->id == ipB->id &&
                ipA->saddr == ipB->saddr &&
                ipA->daddr == ipB->daddr &&
                ipA->protocol == ipB->protocol
        );
    }
};

typedef list< list< IPFragmentInfo> > IPFragmentQueue;
#endif //JIM_SNIFFER_PACKET_H
