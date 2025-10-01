#pragma once
#include <cstdint>
#include <vector>
#include <set>
#include <iostream>
#include "PacketBinary.h"
using namespace std;

struct DnsTransaction
{
    Binary request;
    Binary response;
};

struct DnsReport
{
    int totalDns = 0;   // total pair of {req, res} meaning total transactions
    int failedDns = 0;  // faild transactions
    int successDns = 0; // successful transaction
};

class DnsReporter
{
public:
    void addDnsBinary(const Binary& bin);
    static Binary extractDnsPayload(const Binary &bin);
    static bool isSuccessDnsResponse(const Binary &bin);
    static bool isDnsResponse(const Binary &bin);
    static uint16_t DnstransactionID(const Binary &bin);
    DnsReport getDnsReport(){ return dnsrep; }
private:
    DnsReport dnsrep;
    set<uint16_t> pendingDnsRequests; // dns
};
