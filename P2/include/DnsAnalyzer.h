#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>
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
    int total = 0;
    int failed = 0;
    int success = 0;
};

class DnsReporter {
public:
    void addBinary(const Binary& bin);
    void addDnsTransaction(const DnsTransaction& tx);
    Report getReport() const;

private:
    std::vector<DnsTransaction> transactions;
    std::unordered_map<uint16_t, Binary> pendingRequests;

    bool isSuccessResponse(const Binary& bin) const;
    static bool isResponse(const Binary& bin);
    static uint16_t transactionID(const Binary& bin);
};
