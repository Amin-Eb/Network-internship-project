#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include "PacketUtils.h"
#include <cstring>

using namespace std;

TEST(UtilsTest, packetTypeTest)
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/htmldns.pcapng");
    if (!reader) throw std::runtime_error("Cannot open pcap file");

    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open pcap file");
    }
    
    int cnt_type[4] = {0, 0, 0, 0};
    PacketUtils utils;  
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        Binary bin;
        pcpp::Packet parsed(&rawPacket);
        bin.length = rawPacket.getRawDataLen();
        bin.data = new uint8_t[bin.length];
        std::memcpy(bin.data, rawPacket.getRawData(), bin.length);
        cnt_type[utils.getPacketType(bin)] ++;
    }

    reader->close();
    delete reader;

    EXPECT_EQ(cnt_type[DNS], 142); // 140 pure dns, 2 mdns
    EXPECT_EQ(cnt_type[HTTP], 38); // before packets : 93, 370, 4777 we had 2 segments not included thus 44 http related packets, but 44 - 6 final packets.
    EXPECT_EQ(cnt_type[SIP], 0);
    EXPECT_EQ(cnt_type[NONE], 5156 - 142 - 38);
}
TEST(UtilsTest, packetFlowHashTest)
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/tcp.pcap");
    if (!reader) throw std::runtime_error("Cannot open pcap file");

    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open pcap file");
    }
    
    PacketUtils utils;  
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        Binary bin;
        pcpp::Packet parsed(&rawPacket);
        bin.length = rawPacket.getRawDataLen();
        bin.data = new uint8_t[bin.length];
        std::memcpy(bin.data, rawPacket.getRawData(), bin.length);
        EXPECT_EQ(PacketUtils::flowHash(bin), 4261495774);
    }

    reader->close();
    delete reader;
}