#include "PacketCapture.h"
#include <iostream>
#include <cstring>

using namespace std;

PacketCapture::PacketCapture() : handle(nullptr) { memset(errbuf, 0, sizeof(errbuf)); }

PacketCapture::~PacketCapture() { close(); }

bool PacketCapture::openFile(const string& filename) 
{
    close();
    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle) 
    {
        cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return 0;
    }
    return 1;
}

bool PacketCapture::openInterface(const string& ifname, const string& bpf_filter) 
{
    close();
    handle = pcap_open_live(ifname.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) 
    {
        cerr << "pcap_open_live error: " << errbuf << "\n";
        return 0;
    }

    if (!bpf_filter.empty()) 
    {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) 
        {
            cerr << "pcap_compile failed: " << pcap_geterr(handle) << "\n";
            return 0;
        }
        if (pcap_setfilter(handle, &fp) == -1)
            cerr << "pcap_setfilter failed: " << pcap_geterr(handle) << "\n";
        pcap_freecode(&fp);
    }

    return 1;
}

bool PacketCapture::getNextPacket(Binary& outPacket) 
{
    if (!handle)
    {
        return 0;
    }
    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle, &header, &data);

    if (res == 1) 
    {
        outPacket.length = static_cast<uint16_t>(header->caplen);
        outPacket.data = new uint8_t[outPacket.length];
        memcpy(outPacket.data, data, outPacket.length);
        return true;
    }
    if (res == 0)
    {
        return getNextPacket(outPacket);
    }
    // res == -1 (error) or -2 (EOF)
    return 0;
}

void PacketCapture::close() 
{
    if (handle)
    {
        pcap_close(handle);
        handle = nullptr;
    }
}
