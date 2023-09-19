//
// Created by jimfeng on 23-9-17.
//

#include "sniffer.h"

static char errBuf[PCAP_ERRBUF_SIZE];

Sniffer::Sniffer() = default;

void Sniffer::loadDevices() {
    if(pcap_findalldevs(&devices, errBuf) == PCAP_ERROR){
        cerr << "Err: Can not find devices: " << errBuf << endl;
    }
    int num = 0;
    for(auto dev = devices; dev != nullptr; dev = dev->next) {
        num ++;
    }
    deviceCount = num;
}

void Sniffer::setDevice(int index) {
    if(index >= deviceCount) // 非法参数
        return;
    pcap_if_t *dev = devices;
    currentDeviceIndex = index;
    while(dev && (index -- )){
        dev = dev->next;
    }
    currentDevice = dev;
    qDebug() << "device " << currentDeviceIndex << " selected" << Qt::endl;
}

int Sniffer::getDevicesInfo(vector<string> &info) {
    pcap_if_t *dev = devices;
    while(dev) {
        info.emplace_back(dev->name);
        dev = dev->next;
    }
    return 0;
}

void Sniffer::startListening() {
    if((captureAdaptor = pcap_open_live(currentDevice->name, 65536, 1, 1000, errBuf)) == nullptr) {
        cerr << "Err: Can not open live device: " << currentDevice->name << " " << errBuf << endl;
        return;
    }
    int linkType = pcap_datalink(captureAdaptor);
    if(linkType != DLT_EN10MB){
        puts("Warning: 当前网卡传输层协议不是Ethernet,可能无法正确解析");
    }
    tmpDumpFileName = strdup("/tmp/tmp_fileXXXXXX");
    mkstemp(tmpDumpFileName);
    startCapture();
    isListening = true;
}

void Sniffer::stopListening() {
    pcap_breakloop(captureAdaptor);
    isListening = false;
    saveCapFile("tmp.pcap");
}

void Sniffer::startCapture() {
    pcap_dumper* dumper = nullptr;
    if(tmpDumpFileName != nullptr){
        dumper = pcap_dump_open(captureAdaptor, tmpDumpFileName);
    }
    auto *loop_thread = new thread([](Sniffer* sniffer, pcap_dumper* dumper){
        pcap_loop(sniffer->captureAdaptor, 0, Sniffer::packet_handler, (u_char*)dumper);
        }, this, dumper);
    loop_thread->detach();
    qDebug() << "start capture" << Qt::endl;
}

void Sniffer::loadCapFile(const string &path) {
    if((captureAdaptor = pcap_open_offline(path.c_str(), errBuf)) == nullptr) {
        cerr << "Err: Can not open cap file: " << path << " " << errBuf << endl;
        return;
    }
    startCapture();
}

void Sniffer::packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    // todo: parse packet
    struct tm* packet_time = localtime(&header->ts.tv_sec);
    char timeStr[64];
    strftime(timeStr, sizeof timeStr, "%y-%m-%d %T", packet_time);
    printf("%s  %d\n", timeStr, header->caplen);
    int i = 0;
    while(i < header->caplen)
    {
        printf("%.2x ", pkt_data[i]);
        if ( ((++i) % 16) == 0) printf("\n");
    }
    puts("");
    // dump
    if(user != nullptr){
        pcap_dump(user, header, pkt_data);
    }
}

void Sniffer::saveCapFile(const string &path) {
    if(tmpDumpFileName == nullptr){
        return;
    }
    ifstream tmpFile(tmpDumpFileName, ios::binary);
    ofstream saveFile(path, ios::binary);
    saveFile << tmpFile.rdbuf();
    saveFile.close();
    tmpFile.close();
    tmpDumpFileName = nullptr;
}

