//
// Created by jimfeng on 23-9-18.
//

#include "packet.h"

PacketInfo::PacketInfo(const std::string& info, int start, int end):start(start),end(end) {
    setText(0, QString::fromStdString(info));
}

Packet::Packet(int id, Frame *frame): frameId(id), length(0){
    this->frame = frame;
    parse();
}

string getMacInfo(u_char *mac_start){
    char mac[20];
    snprintf(mac, sizeof mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
              mac_start[0], mac_start[1], mac_start[2], mac_start[3], mac_start[4], mac_start[5]);
    return mac;
}

string getIpAddrInfo(uchar* addr){
    char ip[20];
    snprintf(ip, sizeof ip, "%d.%d.%d.%d",
             addr[0], addr[1], addr[2], addr[3]);
    return ip;
}

void Packet::parse() {
    char timeStr[64];
    data.push_back({frame->raw_data, frame->header->caplen});
    length += frame->header->caplen;
    struct tm* packet_time = localtime(& frame->header->ts.tv_sec);
    auto* macHeader = (ether_header *)frame->raw_data;
    auto dMac = getMacInfo((u_char*)&macHeader->ether_dhost);
    auto sMac = getMacInfo((u_char*)&macHeader->ether_shost);
    auto ethType = ntohs(macHeader->ether_type);
    string infoStr = "Frame time:";
    strftime(timeStr, sizeof timeStr, "%y-%m-%d %T", packet_time);
    infoStr += string(timeStr) + " Src: " + sMac + " Dst: " + dMac;
    src = sMac;
    dst = dMac;
    info = infoStr;
    auto ethInfo = new PacketInfo(infoStr, 0, 14);
    protocolInfo.push_back(ethInfo);
    ethInfo->addChild(new PacketInfo(string("Dst: ") + dMac, 0, 6));
    ethInfo->addChild(new PacketInfo(string("Src: ") + sMac, 6, 12));
    string typeStr = "Type: ";
    auto nextStart = frame->raw_data + 14;
    switch (ethType) {
        case ETHERTYPE_IP:
            typeStr += "IPv4";
            ethInfo->addChild(new PacketInfo(typeStr, 12, 14));
            parse_ip(nextStart, 14);
            break;
        case ETHERTYPE_ARP:
            typeStr += "ARP";
            ethInfo->addChild(new PacketInfo(typeStr, 12, 14));
            parse_arp(nextStart, 14);
            break;
        default:
            typeStr += "Unknown";
            ethInfo->addChild(new PacketInfo(typeStr, 12, 14));
    }
}

void Packet::parse_ip(u_char *start, int baseOffset) {
    auto ipHdr = (iphdr*) start;
    auto version = ipHdr->version;
    auto hdrLen = ipHdr->ihl * 4;
    auto tos = ipHdr->tos;
    auto totLen = ntohs(ipHdr->tot_len);
    auto ident = ntohs(ipHdr->id);
    auto frag = ntohs(ipHdr->frag_off);
    auto sAddr = ipHdr->saddr;
    auto dAddr = ipHdr->daddr;
    auto frag_flag = frag & (~IP_OFFMASK);
    auto frag_off = frag & IP_OFFMASK;
    auto sAddrStr = getIpAddrInfo((uchar*)&sAddr);
    auto dAddrStr = getIpAddrInfo((uchar*)&dAddr);
    auto ipType = "IPv" + to_string(version);
    stringstream ss;
    ss << ipType << " Src: " << sAddrStr << " Dst: " << dAddrStr;
    auto ipInfoStr = ss.str();
    ss.clear();
    src = sAddrStr;
    dst = dAddrStr;
    proto = ipType;
    info = ipInfoStr;
    auto ipInfo = new PacketInfo(ipInfoStr, baseOffset, baseOffset + hdrLen);
    protocolInfo.push_back(ipInfo);
}

void Packet::parse_tcp(u_char *start, int baseOffset) {

}

void Packet::parse_udp(u_char *start, int baseOffset) {

}

void Packet::parse_icmp(u_char *start, int baseOffset) {

}

void Packet::parse_http(u_char *start, int baseOffset) {

}

void Packet::parse_arp(u_char *start, int baseOffset) {

}
