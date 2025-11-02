#include "TcpReporter.h"
#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include "PacketUtils.h"
#include <random>
#include <algorithm>


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
TEST(TcpReporterTest, ReassembleTcpDataCommingInSortedOrder) {
    TcpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/tcp_frags.pcap");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    TcpReporter tcpreporter(sharedrep,"127.0.0.1");
    tcpreporter.setSaveContent(true);
    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin = makeBinaryFromRaw(rawPacket);
        tcpreporter.addTcpBinary(bin);
        delete[] bin.data;
    }

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalTcpPackets.load(),13);
    EXPECT_EQ(sharedrep.bytesUploaded.load(),120874);
    EXPECT_EQ(sharedrep.totalConnections.load(),1);
    EXPECT_EQ(sharedrep.normalClosed.load(), 1);
    EXPECT_EQ(sharedrep.failedHandshakes.load(), 0);

    FILE* pipe = popen("md5sum 127.0.0.1_56824_to_127.0.0.1_12345.txt", "r");
    if (!pipe) 
        EXPECT_FALSE(true);
    
    char buffer[128];
    string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) 
        result += buffer;
    
    EXPECT_EQ(result, "5f37be6997de29884d44af896fae7335  127.0.0.1_56824_to_127.0.0.1_12345.txt\n");
    pclose(pipe);
    return;
}

TEST(TcpReporterTest, ReassembleTcpDataCommingInShuffledOrder) {
    TcpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/tcp_frags.pcap");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    TcpReporter tcpreporter(sharedrep,"127.0.0.1");
    tcpreporter.setSaveContent(true);
    pcpp::RawPacket rawPacket;
    vector<Binary> vc;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin = makeBinaryFromRaw(rawPacket);
        vc.push_back(bin);
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Shuffle the vector
    std::shuffle(vc.begin() + 2, vc.end() -3, gen); //skip befor and after of stablished part

    for(Binary bin : vc) tcpreporter.addTcpBinary(bin),delete[] bin.data;

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalTcpPackets.load(),13);
    EXPECT_EQ(sharedrep.bytesUploaded.load(),120874);
    EXPECT_EQ(sharedrep.totalConnections.load(),1);
    EXPECT_EQ(sharedrep.normalClosed.load(), 1);
    EXPECT_EQ(sharedrep.failedHandshakes.load(), 0);

    FILE* pipe = popen("md5sum 127.0.0.1_56824_to_127.0.0.1_12345.txt", "r");
    if (!pipe) 
        EXPECT_FALSE(true);
    
    char buffer[128];
    string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) 
        result += buffer;
    
    EXPECT_EQ(result, "5f37be6997de29884d44af896fae7335  127.0.0.1_56824_to_127.0.0.1_12345.txt\n");
    pclose(pipe);
    return;
}