//
// Created by jimfeng on 23-9-18.
//

#include "packet.h"

PacketInfo::PacketInfo(const std::string& info, int start, int end, bool reassembled):
    start(start),end(end),reassembled(reassembled) {
    setText(0, QString::fromStdString(info));
}

int PacketInfo::addSubInfo(const string &info, int s, int len) {
    addChild(new PacketInfo(info, s, s +len));
    return s + len;
}

Packet::Packet(int id, Frame *frame): frameId(id), length(0), parsedLength(0){
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

string getInfoByMap(const map<int, string>& mp, int value){
    try{
        return mp.at(value);
    }catch (exception&){
    }
    return "Unknown";
}

string getHexValue(int value, int byteSize) {
    stringstream ss;
    ss << setfill('0') << setw(2*byteSize) << hex << value;
    return "0x" + ss.str();
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
    ethInfo->addSubInfo(string("Dst: ") + dMac, 0, 6);
    ethInfo->addSubInfo(string("Src: ") + sMac, 6, 6);
    auto nextStart = frame->raw_data + 14;
    ethInfo->addSubInfo("Type: " + getInfoByMap({
                                                        {ETHERTYPE_IP,  "IP"},
                                                        {ETHERTYPE_ARP, "ARP"}
                                                }, ethType), 12, 2);
    parsedLength = 14;
    switch (ethType) {
        case ETHERTYPE_IP:
            parseIP(nextStart, 14);
            break;
        case ETHERTYPE_ARP:
            parseARP(nextStart, 14);
            break;
        default:
            break;
    }
}

void Packet::parseIP(u_char *start, int baseOffset) {
    auto ipHdr = (iphdr*) start;
    auto version = ipHdr->version;
    auto hdrLen = ipHdr->ihl * 4;
    auto tos = ipHdr->tos;
    auto totLen = ntohs(ipHdr->tot_len);
    auto ident = ntohs(ipHdr->id);
    auto frag = ntohs(ipHdr->frag_off);
    auto ttl = ipHdr->ttl;
    auto protocol = ipHdr->protocol;
    auto hdrCheck = ntohs(ipHdr->check);
    auto sAddr = ipHdr->saddr;
    auto dAddr = ipHdr->daddr;
    auto protoStr = getInfoByMap({
                                         {IPPROTO_TCP,  "TCP"},
                                         {IPPROTO_UDP,  "UDP"},
                                         {IPPROTO_ICMP, "ICMP"}
                                 }, protocol);
    auto fragFlag = frag & (~IP_OFFMASK);
    auto fragOff = frag & IP_OFFMASK;
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
    baseOffset = ipInfo->addSubInfo(ipType + " Header Len:" + to_string(hdrLen),
                                    baseOffset, 1);
    baseOffset = ipInfo->addSubInfo("Type of Service Field: " + getHexValue(tos, 1),
                                    baseOffset, 1);
    baseOffset = ipInfo->addSubInfo("Total Length: " + to_string(totLen),
                                    baseOffset, 2);
    baseOffset = ipInfo->addSubInfo("Identification: " + getHexValue(ident, 2),
                                    baseOffset, 2);
    baseOffset = ipInfo->addSubInfo("Flag: " + getInfoByMap({
        {IP_DF, "Don't fragment"},
        {IP_MF, "More fragments"},
        {0, "No more fragment"}
    }, fragFlag) + ",Fragment Offset:" + to_string(fragOff*8), baseOffset, 2);
    baseOffset = ipInfo->addSubInfo("TTL:" + to_string(ttl), baseOffset, 1);
    baseOffset = ipInfo->addSubInfo("Protocol:" + protoStr, baseOffset, 1);
    baseOffset = ipInfo->addSubInfo("Header Checksum:" + getHexValue(hdrCheck, 2),
                                    baseOffset, 2);
    baseOffset = ipInfo->addSubInfo("Src Addr:" + sAddrStr, baseOffset, 4);
    baseOffset = ipInfo->addSubInfo("Dst Addr:" + dAddrStr, baseOffset, 4);
    parsedLength = baseOffset;
    if(fragFlag != IP_DF){
        info += "[fragment]";
        ipInfo->addSubInfo("Fragment Data", baseOffset, (int)frame->header->caplen - baseOffset);
        return;
    }

}

void Packet::parseTCP(u_char *start, int baseOffset) {

}

void Packet::parseUDP(u_char *start, int baseOffset) {

}

void Packet::parseICMP(u_char *start, int baseOffset) {

}

void Packet::parseHTTP(u_char *start, int baseOffset) {

}

void Packet::parseARP(u_char *start, int baseOffset) {

}

string Packet::getData(bool reassembled) {
    stringstream ss;
    auto it = data.begin();
    if(reassembled){
        it++;
    }
    uint cnt = 0;
    for(int i = 0; (i < length && !reassembled) || (it != data.end() && reassembled);) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (int) it->start[cnt];
        if((++i)%16 == 0) {
            ss << endl;
        }else {
            ss << " ";
        }
        if(it->len == cnt) {
            it++;
            cnt = 0;
        }else {
            cnt ++;
        }
    }
    return ss.str();
}
