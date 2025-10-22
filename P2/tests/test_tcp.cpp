#include "TcpReporter.h"
#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include "PacketUtils.h"


using namespace std;

Binary makeBinaryFromRaw(const pcpp::RawPacket& raw) {
    Binary bin;
    bin.length = raw.getRawDataLen();
    bin.data = new uint8_t[bin.length];
    std::memcpy(bin.data, raw.getRawData(), bin.length);
    return bin;
}
TEST(TcpReporterTest, SampleCreatedTcpStatistics) {
    TcpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/tcp.pcap");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    TcpReporter tcpreporter(sharedrep,"127.0.0.1");
    pcpp::RawPacket rawPacket;
    int dnsCount = 0;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin = makeBinaryFromRaw(rawPacket);
        tcpreporter.addTcpBinary(bin);
        dnsCount++;
        delete[] bin.data;
    }

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalTcpPackets.load(),8);
    EXPECT_EQ(sharedrep.bytesUploaded.load(),550);
    EXPECT_EQ(sharedrep.totalConnections.load(),1);
    EXPECT_EQ(sharedrep.normalClosed.load(), 1);
    EXPECT_EQ(sharedrep.failedHandshakes.load(), 0);
    return;
}
TEST(TcpReporterTest, RecognizesTcpOnesAmongAll) {
    TcpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/htmldns.pcapng");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    TcpReporter tcpreporter(sharedrep,"192.168.1.104");
    pcpp::RawPacket rawPacket;
    int dnsCount = 0;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin = makeBinaryFromRaw(rawPacket);
        tcpreporter.addTcpBinary(bin);
        dnsCount++;
        delete[] bin.data;
    }

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalTcpPackets.load(),4852);
    return;
}