//
// Created by jimfeng on 23-9-18.
//

#ifndef JIM_SNIFFER_PACKET_H
#define JIM_SNIFFER_PACKET_H
#include <QTreeWidgetItem>
#include "frame.h"

class PacketInfo: QTreeWidgetItem{
public:
    int start;
    int end;
    PacketInfo(const std::string& info, int start, int end);
};

class Packet {
public:
    Packet(Frame *frame);

};


#endif //JIM_SNIFFER_PACKET_H
