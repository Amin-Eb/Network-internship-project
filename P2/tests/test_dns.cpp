#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include "DnsAnalyzer.h"

using namespace std;
Binary makeBinaryFromRaw(const pcpp::RawPacket& raw) {
    Binary bin;
    bin.length = raw.getRawDataLen();
    bin.data = new uint8_t[bin.length];
    std::memcpy(bin.data, raw.getRawData(), bin.length);
    return bin;
}

TEST(DnsReporterTest, GetInitialReport){
    DnsReporter reporter;
    EXPECT_EQ(0, reporter.getReport().recieved);
    EXPECT_EQ(0, reporter.getReport().success);
    EXPECT_EQ(0, reporter.getReport().failed);
    EXPECT_EQ(0, reporter.getReport().total);
}


TEST(DnsReporterTest, ValidPcapTransactionsFile) {
    Report rep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("../samples/capture.pcapng");
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader\n";
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file \n";
        delete reader;
    }

    DnsReporter reporter;
    pcpp::RawPacket rawPacket;
    int dnsCount = 0;

    while (reader->getNextPacket(rawPacket)) {
    //    cout << "count is " << dnsCount << endl;
        pcpp::Packet parsed(&rawPacket);
        auto* dns = parsed.getLayerOfType<pcpp::DnsLayer>();
        if (!dns) continue; // skip non-DNS

        Binary bin = makeBinaryFromRaw(rawPacket);
        reporter.addBinary(bin);
        dnsCount++;
        delete[] bin.data;
    }

    


    reader->close();
    delete reader;
    rep = reporter.getReport();
    EXPECT_EQ(rep.recieved, dnsCount);
    EXPECT_EQ(rep.success, 22);
    EXPECT_EQ(rep.failed, 1);
    return;
}
