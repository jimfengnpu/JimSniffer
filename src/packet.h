//
// Created by jimfeng on 23-9-18.
//

#ifndef JIM_SNIFFER_PACKET_H
#define JIM_SNIFFER_PACKET_H
#include <QTreeWidgetItem>
#include <QListWidgetItem>
#include <sstream>
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
    int start;
    int end;
    PacketInfo(const std::string& info, int start, int end);
    int addSubInfo(const string& info, int s, int len);
};

typedef struct {
    u_char *start;
    uint len;
} PacketDataInfo;

class Packet {
public:
    int frameId;
    string src;
    string dst;
    string proto;
    string info;
    Frame *frame;
    uint length;
    vector<PacketDataInfo> data;
    vector<PacketInfo*> protocolInfo;
    explicit Packet(int id, Frame *frame);
    void parse();
    void parse_ip(u_char *start, int baseOffset);
    void parse_tcp(u_char *start, int baseOffset);
    void parse_udp(u_char *start, int baseOffset);
    void parse_icmp(u_char *start, int baseOffset);
    void parse_http(u_char *start, int baseOffset);
    void parse_arp(u_char *start, int baseOffset);
};


#endif //JIM_SNIFFER_PACKET_H
