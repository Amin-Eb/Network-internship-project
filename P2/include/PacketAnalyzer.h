#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <iostream>
#include "PacketBinary.h"
#include "DnsReporter.h"
#include "HttpReporter.h"
#include "SipReporter.h"

enum PacketType {
    DNS = 0,
    HTTP = 1,
    SIP = 2,
    NONE = 3,
};


struct Report
{
    DnsReport dnsreport;
    HttpReport httpreport;
    SipReport sipreport;

    int recieved = 0; // all recieved packets
};

class Reporter
{
public:
    void addBinary(const Binary &bin);
    static int getPacketType(const Binary &bin);
    Report getReport() const;

private:
    Report rep;
    DnsReporter dnsreporter;
    HttpReporter httpreporter;
    SipReporter sipreporter;
};