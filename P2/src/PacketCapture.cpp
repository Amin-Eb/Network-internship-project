// src/PacketCapture.cpp
#include "PacketCapture.h"
#include <pcap/pcap.h>
#include <cstring>
#include <iostream>

int PacketCapture::fromFile(const std::string& filename, Reporter& analyzer) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_offline(filename.c_str(), errbuf);
    if (!p) {
        std::cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int res;
    while ((res = pcap_next_ex(p, &header, &data)) >= 0) {
        if (res == 0) continue;

        Binary bin;
        bin.length = static_cast<uint16_t>(header->caplen);
        bin.data = new uint8_t[bin.length];
        std::memcpy(bin.data, data, bin.length);

        analyzer.addBinary(bin);

        delete[] bin.data;
    }

    if (res == -1)
        std::cerr << "pcap read error: " << pcap_geterr(p) << "\n";

    pcap_close(p);
    return 0;
}

int PacketCapture::fromInterface(const std::string& ifname,
                                  const std::string& bpf_filter,
                                  Reporter& analyzer,
                                  int limit) {// if no limit set by user, cnt never == cnt == 0 so no stop!
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_live(ifname.c_str(), 65535, 1, 1000, errbuf);
    if (!p) {
        std::cerr << "pcap_open_live error: " << errbuf << "\n";
        return -1;
    }

    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(p, &fp, bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "pcap_compile failed: " << pcap_geterr(p) << "\n";
            return -2;
        } else {
            if (pcap_setfilter(p, &fp) == -1)
                std::cerr << "pcap_setfilter failed: " << pcap_geterr(p) << "\n";
            pcap_freecode(&fp);
        }
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int res;
    int cnt = 0;
    while ((res = pcap_next_ex(p, &header, &data)) >= 0) {
        cnt ++;
        if (res == 0) continue;

        Binary bin;
        bin.length = static_cast<uint16_t>(header->caplen);
        bin.data = new uint8_t[bin.length];
        std::memcpy(bin.data, data, bin.length);

        analyzer.addBinary(bin);

        delete[] bin.data;
        if(cnt == limit) return 0;
    }

    if (res == -1){
        std::cerr << "pcap read error: " << pcap_geterr(p) << "\n";
        return -3;
    }

    pcap_close(p);
    return 0;
}
