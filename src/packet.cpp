//
// Created by jimfeng on 23-9-18.
//

#include "packet.h"

PacketInfo::PacketInfo(const std::string& info, int start, int end):start(start),end(end) {
    setText(0, QString::fromStdString(info));
}

Packet::Packet(int id, Frame *frame): frameId(id){
    this->frame = frame;
    parse();
}

string getMacInfo(u_char *mac_start){
    char mac[20];
    snprintf(mac, sizeof mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
              mac_start[0], mac_start[1], mac_start[2], mac_start[3], mac_start[4], mac_start[5]);
    return mac;
}

void Packet::parse() {
    struct tm* packet_time = localtime(& frame->header->ts.tv_sec);
    char timeStr[64];
    strftime(timeStr, sizeof timeStr, "%y-%m-%d %T", packet_time);
    auto* macHeader = (ether_header *)frame->raw_data;
    string infoStr = "Frame time:";
    auto dMac = getMacInfo((u_char*)&macHeader->ether_dhost);
    auto sMac = getMacInfo((u_char*)&macHeader->ether_shost);
    infoStr += string(timeStr) + " Src: " + sMac + " Dst: " + dMac;
    src = sMac;
    dst = dMac;
    info = infoStr;
    auto ethInfo = new PacketInfo(infoStr, 0, 14);
    protocolInfo.push_back(ethInfo);
    ethInfo->addChild(new PacketInfo(string("Dst: ") + dMac, 0, 6));
    ethInfo->addChild(new PacketInfo(string("Src: ") + sMac, 6, 12));
    string typeStr = "Type: ";
    switch (ntohs(macHeader->ether_type)) {
        case ETHERTYPE_IP:
            typeStr += "IPv4";
            ethInfo->addChild(new PacketInfo(typeStr, 12, 14));
            parse_ip(frame->raw_data + 14);
            break;
        case ETHERTYPE_ARP:
            typeStr += "ARP";
            ethInfo->addChild(new PacketInfo(typeStr, 12, 14));
            parse_arp(frame->raw_data + 14);
            break;
        default:
            typeStr += "Unknown";
            ethInfo->addChild(new PacketInfo(typeStr, 12, 14));
    }
}

void Packet::parse_ip(u_char *start) {

}

void Packet::parse_tcp(u_char *start) {

}

void Packet::parse_udp(u_char *start) {

}

void Packet::parse_icmp(u_char *start) {

}

void Packet::parse_http(u_char *start) {

}

void Packet::parse_arp(u_char *start) {

}
