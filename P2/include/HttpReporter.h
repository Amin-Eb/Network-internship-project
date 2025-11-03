#pragma once
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <set>
#include <cstring>
#include <stdexcept>
#include <atomic>
#include "PacketBinary.h"
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>
using namespace std;

struct HttpReport
{
    atomic<int> totalHttp{0};   // total tuple of {req, res1, req2, req3, res2, req4, ...}
    atomic<int> failedHttp{0};  // faild Http FullRequests
    atomic<int> successHttp{0}; // successful Http FullRequests
};

class HttpReporter
{
public:
    explicit HttpReporter(HttpReport& sharedReport)
        : httprep(sharedReport) {}

    void addHttpBinary(const Binary& bin);
    static Binary extractHttpPayload(const Binary& bin);
    static bool isSuccessHttpResponse(const Binary &bin);
    static std::string httpMethod(const Binary& bin);
    static int httpStatusCode(const Binary& bin);
    static bool isHttpResponse(const Binary& bin);
    HttpReport& getHttpReport(){ return httprep; }
    int pendingRequestsCount(){ return pendingHttpRequests.size(); }
private:
    HttpReport& httprep;
    std::set<uint32_t> pendingHttpRequests; // key: TCP ack number of reqs, http
    std::map<uint32_t, int> pendingHttpResponses;
};