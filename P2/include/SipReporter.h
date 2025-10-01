#pragma once
#include <cstdint>
#include <vector>
#include <map>
#include <set>
#include <iostream>
#include "PacketBinary.h"
using namespace std;

struct SipReport
{
    int totalSip = 0;    // total series of {req, res1, res2, res3} : INVITE => 180 Ringing => 200 OK => ACK.
    int failedSip = 0;   // faild sip requests
    int successSip = 0;  // successful sip requests
};

class SipReporter
{
public:
    static Binary extractSipPayload(const Binary &bin);
    static std::string extractSipCallId(const Binary &bin);
    static bool isSip(const Binary& bin);
    static bool isSuccessSipResponse(const Binary &bin);
    static bool isSipResponse(const Binary &bin);
    static int sipStatusCode(const Binary &bin);
    void addSipBinary(const Binary& bin);
    SipReport getSipReport() { return siprep; }; 
private:
    SipReport siprep;
    set<string> sipRequests;
};



