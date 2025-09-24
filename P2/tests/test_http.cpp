#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include "PacketAnalyzer.h"
#include <cstring>

using namespace std;

// Helper to create Binary from raw data
Binary makeBinaryFromRaw(const uint8_t* data, size_t len) {
    Binary bin;
    bin.length = static_cast<uint16_t>(len);
    bin.data = new uint8_t[bin.length];
    memcpy(bin.data, data, bin.length);
    return bin;
}

// Sample HTTP request packet
Binary makeTestHttpRequest() {
    static uint8_t packet[14 + 20 + 32 + 24] = {0};

    // Ethernet (14)
    packet[12] = 0x08;
    packet[13] = 0x00; // IPv4

    // IPv4 (20)
    packet[14] = 0x45; // IHL=5, no options

    // TCP (32) - assume fixed, dummy values
    // ...

    // HTTP payload (24 bytes) - "GET /index.html HTTP/1.1\r\n"
    const char* httpReq = "GET /index.html HTTP/1.1\r\n";
    memcpy(packet + 14 + 20 + 32, httpReq, strlen(httpReq));

    return makeBinaryFromRaw(packet, sizeof(packet));
}

// Sample HTTP response packet
Binary makeTestHttpResponse() {
    static uint8_t packet[14 + 20 + 32 + 27] = {0};

    // Ethernet + IP + TCP same as above

    // HTTP payload - "HTTP/1.1 200 OK\r\nContent"
    const char* httpRes = "HTTP/1.1 200 OK\r\nContent";
    memcpy(packet + 14 + 20 + 32, httpRes, strlen(httpRes));

    return makeBinaryFromRaw(packet, sizeof(packet));
}

TEST(HttpReporterTest, ExtractHttpPayload) {
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    // Assume you have a method extractHttpPayload(Binary)
    Binary reqPayload = Reporter::extractHttpPayload(req);
    Binary resPayload = Reporter::extractHttpPayload(res);

    EXPECT_EQ(reqPayload.length, req.length - 14 - 20 - 32);
    EXPECT_EQ(resPayload.length, res.length - 14 - 20 - 32);

    EXPECT_EQ(strncmp((char*)reqPayload.data, "GET /index.html", 15), 0);
    EXPECT_EQ(strncmp((char*)resPayload.data, "HTTP/1.1 200 OK", 15), 0);

    delete[] req.data;
    delete[] res.data;
}

TEST(HttpReporterTest, IsHttpRequestAndResponse) { 
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    EXPECT_FALSE(Reporter::isHttpResponse(req));

    EXPECT_TRUE(Reporter::isHttpResponse(res));

    delete[] req.data;
    delete[] res.data;
}

TEST(HttpReporterTest, HttpStatusCodeAndMethod) {
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    EXPECT_EQ(Reporter::httpMethod(req), "GET");
    EXPECT_EQ(Reporter::httpStatusCode(res), 200);

    delete[] req.data;
    delete[] res.data;
}

TEST(HttpReporterTest, AddHttpBinaryIncreasesReport) {
    Reporter reporter;
    Binary req = makeTestHttpRequest();
    Binary res = makeTestHttpResponse();

    reporter.addBinary(req);
    reporter.addBinary(res);

    Report rep = reporter.getReport();
    EXPECT_EQ(rep.recieved, 2);
    EXPECT_EQ(rep.successHttp, 1); // after matching request/response
    EXPECT_EQ(rep.failedHttp, 0);

    delete[] req.data;
    delete[] res.data;
}
