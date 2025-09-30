#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <iostream>
#include "PacketBinary.h"
#include "DnsReporter.h"
#include "HttpReporter.h"

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

    int totalSip = 0;    // total series of {req, res1, res2, res3} : INVITE => 180 Ringing => 200 OK => ACK.
    int failedSip = 0;   // faild sip requests
    int successSip = 0;  // successful sip requests

    int recieved = 0; // all recieved packets
};

class Reporter
{
public:
    void addBinary(const Binary &bin);
    static int getPacketType(const Binary &bin);

   
    
    // sip stuff
    static Binary extractSipPayload(const Binary &bin);
    static bool isSip(const Binary& bin);
    static bool isSuccessSipResponse(const Binary &bin);
    static bool isSipResponse(const Binary &bin);
    static int sipStatusCode(const Binary &bin);
    Report getReport() const;

private:
    void addSipBinary(const Binary& bin);

    Report rep;
    DnsReporter dnsreporter;
    HttpReporter httpreporter;
};