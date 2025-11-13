#include "SctpReporter.h"
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
TEST(SctpReporterTest, SampleCreatedSctpStatistics) {
    SctpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/sctp-www.cap");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    SctpReporter sctpreporter(sharedrep,"155.230.24.155");
    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin = makeBinaryFromRaw(rawPacket);
        sctpreporter.addSctpBinary(bin);
        delete[] bin.data;
    }

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalSctpPackets.load(),84);
    EXPECT_EQ(sharedrep.totalAssociations.load(),3); // 2 assoc with normal start and end; 3 attempts for creating 'one' assoc, we count that tried but not done communication as 1
    EXPECT_EQ(sharedrep.openAssociations.load(),1);
    EXPECT_EQ(sharedrep.normalClosed.load(),2);

    return;
}

TEST(SctpReporterTest, ReassembleSctpDataCommingInSortedOrder) {
    SctpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/sctp-www.cap");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    SctpReporter sctpreporter(sharedrep,"155.230.24.155");
    sctpreporter.addSctpClient("155.230.24.156");
    sctpreporter.setSaveContent(true);
    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        Binary bin = makeBinaryFromRaw(rawPacket);
        sctpreporter.addSctpBinary(bin);
        delete[] bin.data;
    }

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalSctpPackets.load(),84);
    EXPECT_EQ(sharedrep.totalAssociations.load(),3); // 2 assoc with normal start and end; 3 attempts for creating 'one' assoc, we count that tried but not done communication as 1
    EXPECT_EQ(sharedrep.openAssociations.load(),1);
    EXPECT_EQ(sharedrep.normalClosed.load(),2);

    FILE* pipe = popen("md5sum 155.230.24.155_32836_to_203.255.252.194_80_stream_3.bin", "r"); // the image file
    if (!pipe) 
        EXPECT_FALSE(true);
    
    char buffer[128];
    string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) 
        result += buffer;
    
    EXPECT_EQ(result, "d9aeaef2a3e33b942a39ea143b3b189f  155.230.24.155_32836_to_203.255.252.194_80_stream_3.bin\n");
    pclose(pipe);
    return; 
}

TEST(TcpReporterTest, ReassembleTcpDataCommingInShuffledOrder) {
    SctpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/sctp-www.cap");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    SctpReporter sctpreporter(sharedrep,"127.0.0.1");
    sctpreporter.setSaveContent(true);
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
    std::shuffle(vc.begin() + 4, vc.end() -4, gen); //skip befor and after of stablished part

    for(Binary bin : vc) sctpreporter.addSctpBinary(bin),delete[] bin.data;

    reader->close();
    delete reader;
    EXPECT_EQ(sharedrep.totalSctpPackets.load(),84);
    EXPECT_EQ(sharedrep.totalAssociations.load(),3); // 2 assoc with normal start and end; 3 attempts for creating 'one' assoc, we count that tried but not done communication as 1
    EXPECT_EQ(sharedrep.openAssociations.load(),1);
    EXPECT_EQ(sharedrep.normalClosed.load(),2);

    FILE* pipe = popen("md5sum 155.230.24.155_32836_to_203.255.252.194_80_stream_3.bin", "r"); // the image file
    if (!pipe) 
        EXPECT_FALSE(true);
    
    char buffer[128];
    string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) 
        result += buffer;
    
    EXPECT_EQ(result, "d9aeaef2a3e33b942a39ea143b3b189f  155.230.24.155_32836_to_203.255.252.194_80_stream_3.bin\n");
    pclose(pipe);
    return; 
}
