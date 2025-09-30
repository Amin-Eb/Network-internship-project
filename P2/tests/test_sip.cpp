#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SipLayer.h>
#include "PacketAnalyzer.h"
#include <cstring>

// convert RawPacket -> Binary
Binary makeBinaryFromRaw(const pcpp::RawPacket& raw) {
    Binary bin;
    bin.length = raw.getRawDataLen();
    bin.data = new uint8_t[bin.length];
    std::memcpy(bin.data, raw.getRawData(), bin.length);
    return bin;
}

// Get first SIP request using SipLayer of pcap++
Binary makeTestSipRequest() {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/sip.pcapng");
    if (!reader) throw std::runtime_error("Cannot open pcap file");
    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open sip.pcapng");
    }
    //std::cout << "openedreq\n";
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        auto* sipReq = parsed.getLayerOfType<pcpp::SipRequestLayer>();
        if (sipReq) {
            Binary bin;
            bin.length = rawPacket.getRawDataLen();
            bin.data = new uint8_t[bin.length];
            std::memcpy(bin.data, rawPacket.getRawData(), bin.length);
            reader->close();
            delete reader;
            return bin;
        }
    }

    reader->close();
    delete reader;
    throw std::runtime_error("No SIP request found");
}

// Get first SIP response using SipLayer of pcap++
Binary makeTestSipResponse() {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/sip.pcapng");
    if (!reader) throw std::runtime_error("Cannot open pcap file");
    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open sip.pcapng");
    }
    //std::cout << "openedres\n";
    int i = 0;
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        i++;
        pcpp::Packet parsed(&rawPacket);
        auto* sipRes = parsed.getLayerOfType<pcpp::SipResponseLayer>();
        if (sipRes) {
            Binary bin;
            bin.length = rawPacket.getRawDataLen();
            bin.data = new uint8_t[bin.length];
            std::memcpy(bin.data, rawPacket.getRawData(), bin.length);
            reader->close();
            delete reader;
            std::cout << "Found SIP response at packet " << i << "\n";
            return bin;
        }
    }

    reader->close();
    delete reader;
    throw std::runtime_error("No SIP response found");
}

TEST(SipReporterTest, DetectSipPackets) {
    Binary req = makeTestSipRequest();
    Binary res = makeTestSipResponse();

    EXPECT_TRUE(SipReporter::isSip(req));
    EXPECT_TRUE(SipReporter::isSip(res));

    EXPECT_FALSE(SipReporter::isSipResponse(req));
    EXPECT_TRUE(SipReporter::isSipResponse(res));
    delete[] req.data;
    delete[] res.data;
}

TEST(SipReporterTest, ParseSipStatusCode) {
    Binary res = makeTestSipResponse();
    int code = SipReporter::sipStatusCode(res);
    EXPECT_EQ(code, 100);
}

TEST(SipReporterTest, AddSipBinaryUpdatesReport) {
    Reporter reporter;
    Binary req = makeTestSipRequest();
    Binary res = makeTestSipResponse();

    reporter.addBinary(req);
    reporter.addBinary(res);

    Report rep = reporter.getReport();
    EXPECT_EQ(rep.recieved, 2);
    EXPECT_EQ(rep.sipreport.totalSip, 1);
    //EXPECT_EQ(rep.successSip + rep.failedSip, 1); no! because we havnt full res of the req to decide

    delete[] req.data;
    delete[] res.data;
}

TEST(SipReporterTest, FullPcapScanWithSipLayer) {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/sip.pcapng");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open());

    Reporter reporter;
    pcpp::RawPacket rawPacket;
    int sipCount = 0;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        auto* sipLayer = parsed.getLayerOfType<pcpp::SipLayer>();
        if (!sipLayer) continue;

        Binary bin = makeBinaryFromRaw(rawPacket);
        reporter.addBinary(bin);
        sipCount++;
        EXPECT_EQ(reporter.getReport().recieved, sipCount);
        delete[] bin.data;
    }

    reader->close();
    delete reader;

    Report rep = reporter.getReport();
    EXPECT_EQ(rep.sipreport.totalSip, 94); //included "MESSAGE"  and "BYE " sip requests beside of other normal ones
    EXPECT_EQ(rep.recieved, sipCount);
    EXPECT_EQ(rep.sipreport.failedSip, 1); // TODO , no res reqs count as failed!
    EXPECT_EQ(rep.sipreport.successSip, 6);
}
