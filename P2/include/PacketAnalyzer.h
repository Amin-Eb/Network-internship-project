#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <iostream>

enum PacketType {
    DNS = 0,
    HTTP = 1
};

struct Binary
{
    uint8_t *data;
    uint16_t length;
};

struct DnsTransaction
{
    Binary request;
    Binary response;
};

struct Report
{
    int totalDns = 0;   // total pair of {req, res} meaning total transactions
    int failedDns = 0;  // faild transactions
    int successDns = 0; // successful transaction

    int totalHttp = 0;   // total tuple of {req, res1, req2, req3, res2, req4, ...}
    int failedHttp = 0;  // faild Http FullRequests
    int successHttp = 0; // successful Http FullRequests

    int recieved = 0; // all recieved packets
};

class Reporter
{
public:
    void addBinary(const Binary &bin);
    static int getPacketType(const Binary &bin);

    // dns stuff
    static Binary extractDnsPayload(const Binary &bin);
    static bool isSuccessDnsResponse(const Binary &bin);
    static bool isDnsResponse(const Binary &bin);
    static uint16_t DnstransactionID(const Binary &bin);

    // http stuff
    static Binary extractHttpPayload(const Binary& bin);
    static bool isSuccessHttpResponse(const Binary &bin);
    static std::string httpMethod(const Binary& bin);
    static int httpStatusCode(const Binary& bin);
    static bool isHttpResponse(const Binary& bin);

    
    Report getReport() const;

private:
    void addDnsBinary(const Binary& bin);
    void addHttpBinary(const Binary& bin);
    Report rep;
    std::map<uint16_t, Binary> pendingRequests;
};