#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include "PacketAnalyzer.h"
#include "DnsReporter.h"
#include <cstring>

using namespace std;

TEST(AnalyzerTest, packetTypeTest)
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/htmldns.pcapng");
    if (!reader) throw std::runtime_error("Cannot open pcap file");

    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open pcap file");
    }
    
    int cnt_type[4] = {0, 0, 0, 0};

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin;
        bin.length = rawPacket.getRawDataLen();
        bin.data = new uint8_t[bin.length];
        std::memcpy(bin.data, rawPacket.getRawData(), bin.length);
        cnt_type[Reporter::getPacketType(bin)] ++;
    }

    reader->close();
    delete reader;

    EXPECT_EQ(cnt_type[DNS], 142); // 140 pure dns, 2 mdns
    EXPECT_EQ(cnt_type[HTTP], 44); // 42 pure http, 2 more deassembled
    EXPECT_EQ(cnt_type[SIP], 0);
    EXPECT_EQ(cnt_type[NONE], 5156 - 142 - 44);
}