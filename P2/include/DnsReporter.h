#pragma once
#include <cstdint>
#include <vector>
#include <set>
#include <iostream>
#include <atomic>
#include "PacketBinary.h"
using namespace std;

struct DnsTransaction
{
    Binary request;
    Binary response;
};

struct DnsReport
{
    atomic<int> totalDns{0};   // total pair of {req, res} meaning total transactions
    atomic<int> failedDns{0};  // faild transactions
    atomic<int> successDns{0}; // successful transaction
};

class DnsReporter
{
public:
    explicit DnsReporter(DnsReport& sharedReport)
        : dnsrep(sharedReport) {}

    void addDnsBinary(const Binary& bin);
    static Binary extractDnsPayload(const Binary &bin);
    static bool isSuccessDnsResponse(const Binary &bin);
    static bool isDnsResponse(const Binary &bin);
    static uint16_t DnstransactionID(const Binary &bin);
    DnsReport& getDnsReport(){ return dnsrep; }
private:
    DnsReport& dnsrep;
    set<uint16_t> pendingDnsRequests; // dns
};
