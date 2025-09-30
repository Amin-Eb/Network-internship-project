#pragma once
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <stdexcept>
#include "PacketBinary.h"
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>

struct HttpReport
{
    int totalHttp = 0;   // total tuple of {req, res1, req2, req3, res2, req4, ...}
    int failedHttp = 0;  // faild Http FullRequests
    int successHttp = 0; // successful Http FullRequests
};

class HttpReporter
{
public:
    void addHttpBinary(const Binary& bin);
    static Binary extractHttpPayload(const Binary& bin);
    static bool isSuccessHttpResponse(const Binary &bin);
    static std::string httpMethod(const Binary& bin);
    static int httpStatusCode(const Binary& bin);
    static bool isHttpResponse(const Binary& bin);
    HttpReport getHttpReport(){ return httprep; }
private:
    HttpReport httprep;
    std::map<uint32_t, Binary> pendingHttpRequests; // key: TCP ack number , http
};