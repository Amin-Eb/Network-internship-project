#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <set>
#include <iostream>
#include <atomic>
#include "PacketBinary.h"
using namespace std;

struct SipReport
{
    atomic<int> totalSip = 0;    // total series of {req, res1, res2, res3} : INVITE => 180 Ringing => 200 OK => ACK.
    atomic<int> failedSip = 0;   // faild sip requests
    atomic<int> successSip = 0;  // successful sip requests
};

class SipReporter
{
public:
    explicit SipReporter(SipReport& sharedReport)
        : siprep(sharedReport) {}

    static Binary extractSipPayload(const Binary &bin);
    static std::string extractSipCallId(const Binary &bin);
    static bool isSip(const Binary& bin);
    static bool isSuccessSipResponse(const Binary &bin);
    static bool isSipResponse(const Binary &bin);
    static int sipStatusCode(const Binary &bin);
    void addSipBinary(const Binary& bin);
    SipReport& getSipReport() { return siprep; }; 
private:
    SipReport& siprep;
    set<string> sipRequests;
};



