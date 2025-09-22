#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <iostream>

struct Binary {
    uint8_t* data;
    uint16_t length;
};

struct DnsTransaction {
    Binary request;
    Binary response;
};

struct Report {
    int total = 0; // total pair of {req, res} meaning total transactions
    int failed = 0; // faild transactions
    int success = 0; // successful transaction
    int recieved = 0; // all recieved packets
};

class DnsReporter {
public:
    void addBinary(const Binary& bin);
    Report getReport() const;

private:
    Report rep;
    std::map<uint16_t, Binary> pendingRequests;
    inline static Binary extractDnsPayload(const Binary& bin);
    static bool isSuccessResponse(const Binary& bin);
    static bool isResponse(const Binary& bin);
    static uint16_t transactionID(const Binary& bin);
};