//
// Created by jimfeng on 23-9-18.
//

#include "packet.h"

PacketInfo::PacketInfo(const std::string& info, int start, int end):start(start),end(end) {
    setText(0, QString::fromStdString(info));
}

Packet::Packet(Frame *frame) {

}
