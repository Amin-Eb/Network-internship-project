#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <iostream>
#include <atomic>
#include "PacketBinary.h"
#include "DnsReporter.h"
#include "HttpReporter.h"
#include "SipReporter.h"
#include "PacketUtils.h"

struct Report
{
    DnsReport* dnsreport;
    HttpReport* httpreport;
    SipReport* sipreport;

    atomic<int> recieved = 0; // all recieved packets
};

class Reporter
{
public:
    explicit Reporter(Report& sharedReport)
        : rep(sharedReport),
          dnsreporter(*sharedReport.dnsreport),
          httpreporter(*sharedReport.httpreport),
          sipreporter(*sharedReport.sipreport) {}

    void addBinary(const Binary &bin);
    Report& getReport() const;

private:
    PacketUtils utils;
    Report& rep;
    DnsReporter dnsreporter;
    HttpReporter httpreporter;
    SipReporter sipreporter;
};