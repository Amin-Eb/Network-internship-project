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

class DnsReporter {
public:
    void addBinary(const Binary& bin);
    void addDnsTransaction(const DnsTransaction& tx);
    void getReport() const;

private:
    std::vector<DnsTransaction> transactions;
    std::unordered_map<uint16_t, Binary> pendingRequests;

    static bool isResponse(const Binary& bin);
    static uint16_t transactionID(const Binary& bin);
};
