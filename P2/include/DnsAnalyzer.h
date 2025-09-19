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
    void addDnsTransaction(const DnsTransaction& tx);
    Report getReport() const;

private:
    Report rep;
    std::map<uint16_t, Binary> pendingRequests;
    bool isSuccessResponse(const Binary& bin) const;
    static bool isResponse(const Binary& bin);
    static uint16_t transactionID(const Binary& bin);
};