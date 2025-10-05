#pragma once
#include <string>
#include <pcap/pcap.h>
#include "PacketBinary.h"

using namespace std;

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();
    bool openFile(const string& filename);
    bool openInterface(const string& ifname, const string& bpf_filter = "");
    bool getNextPacket(Binary& outPacket);
    void close();

private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
};
