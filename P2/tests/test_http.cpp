#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/HttpLayer.h>
#include "PacketAnalyzer.h"
#include <cstring>

using namespace std;

// RawPacket
Binary makeBinaryFromRaw(const pcpp::RawPacket& raw) {
    Binary bin;
    bin.length = raw.getRawDataLen();
    bin.data = new uint8_t[bin.length];
    std::memcpy(bin.data, raw.getRawData(), bin.length);
    return bin;
}

// For raw buffers
Binary makeBinaryFromRaw(const uint8_t* data, size_t len) {
    Binary bin;
    bin.length = len;
    bin.data = new uint8_t[len];
    std::memcpy(bin.data, data, len);
    return bin;
}

// Sample HTTP request packet
// first i used ai agents for mading sample packets, not worked! so we read real ones.
Binary makeTestHttpRequest() {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/htmldns.pcapng");
    if (!reader) throw std::runtime_error("Cannot open pcap file");

    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open pcap file");
    }

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        if (parsed.getLayerOfType<pcpp::HttpRequestLayer>()) {
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
    throw std::runtime_error("No HTTP request found in pcap");
}

// Sample HTTP response packet
Binary makeTestHttpResponse() {
     pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/htmldns.pcapng");
    if (!reader) throw std::runtime_error("Cannot open pcap file");

    if (!reader->open()) {
        delete reader;
        throw std::runtime_error("Cannot open pcap file");
    }

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);
        if (parsed.getLayerOfType<pcpp::HttpResponseLayer>()) {
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
    throw std::runtime_error("No HTTP response found in pcap");
}

TEST(HttpReporterTest, ExtractHttpPayload) {
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    Binary reqPayload = HttpReporter::extractHttpPayload(req);
    Binary resPayload = HttpReporter::extractHttpPayload(res);

    EXPECT_EQ(reqPayload.length, req.length - 14 - 20 - 32);
    EXPECT_EQ(resPayload.length, res.length - 14 - 20 - 32);

    EXPECT_EQ(strncmp((char*)reqPayload.data, "GET /index.html", 15), 0);
    EXPECT_EQ(strncmp((char*)resPayload.data, "HTTP/1.1 200 OK", 15), 0);

    delete[] req.data;
    delete[] res.data;
    delete[] reqPayload.data;
    delete[] resPayload.data;
}

TEST(HttpReporterTest, IsHttpRequestAndResponse) { 
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    EXPECT_FALSE(HttpReporter::isHttpResponse(req));
    EXPECT_TRUE(HttpReporter::isHttpResponse(res));
}

TEST(HttpReporterTest, HttpStatusCodeAndMethod) {
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    EXPECT_EQ(HttpReporter::httpMethod(req), "GET");
    EXPECT_EQ(HttpReporter::httpStatusCode(res), 200);
}

TEST(HttpReporterTest, AddHttpBinaryIncreasesReport) {
    HttpReport sharedrep;
    HttpReporter httpreporter(sharedrep);
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    httpreporter.addHttpBinary(req);
    httpreporter.addHttpBinary(res);

    EXPECT_EQ(sharedrep.successHttp.load(), 1);
    EXPECT_EQ(sharedrep.failedHttp.load(), 0);
} 

TEST(HttpReporterTest, ValidPcapPacketsFile) {
    HttpReport sharedrep;
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("samples/htmldns.pcapng");
    ASSERT_NE(reader, nullptr);

    ASSERT_TRUE(reader->open());

    HttpReporter httpreporter(sharedrep);
    pcpp::RawPacket rawPacket;
    int httpCount = 0;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsed(&rawPacket);

        auto* httpReq = parsed.getLayerOfType<pcpp::HttpRequestLayer>();
        auto* httpRes = parsed.getLayerOfType<pcpp::HttpResponseLayer>();
        if (!httpReq && !httpRes) continue;

        Binary bin = makeBinaryFromRaw(rawPacket);
        httpreporter.addHttpBinary(bin);
        httpCount++;

        //EXPECT_EQ(reporter.getReport().recieved, httpCount); counting recieved packets isnt this class job! search it in Reporter class tests
        delete[] bin.data;
    }
    reader->close();
    delete reader;

    EXPECT_EQ(sharedrep.successHttp.load(), 21);
    EXPECT_EQ(sharedrep.failedHttp.load(), 1);
    EXPECT_EQ(sharedrep.totalHttp.load(), 44);
    //EXPECT_EQ(rep.recieved, 44); // the file contains 41 pure http packets but two of them are assembeled of more packets so the real is 44
}
