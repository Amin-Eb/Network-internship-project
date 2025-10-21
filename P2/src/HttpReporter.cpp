#include "HttpReporter.h"
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/Packet.h>

void HttpReporter::addHttpBinary(const Binary &bin)
{
    try
    {
        timeval tv{};
        pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
        pcpp::Packet packet(&rawPacket);

        auto tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        uint32_t seqNum = 0;
        uint32_t ackNum = 0;
        if (tcpLayer){
            // the response of each request has that requests ack number as its seq number!
            
            seqNum = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
            ackNum = ntohl(tcpLayer->getTcpHeader()->ackNumber);
        }
        auto httpReq = packet.getLayerOfType<pcpp::HttpRequestLayer>();
        auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();

        if (httpReq)
        {
            httprep.totalHttp++;
            // Keep request until we see a response
            if (seqNum != 0){
                if(pendingHttpResponses.count(ackNum))
                {
                    if(pendingHttpResponses[ackNum] == 1){
                        httprep.successHttp++;
                        pendingHttpResponses.erase(ackNum);
                    }
                    else if(pendingHttpResponses[ackNum] == -1){
                        httprep.failedHttp ++;
                        pendingHttpResponses.erase(ackNum);
                    }
                    
                }
                else 
                {
                    pendingHttpRequests.insert(ackNum);
                    httprep.failedHttp++; // count pending as faild
                }
            }
        }
        else if (httpRes)
        { 
            httprep.totalHttp++;

            int status = httpRes->getFirstLine()->getStatusCode();

            if (seqNum != 0 && pendingHttpRequests.count(seqNum))
            {
                //cout << seqNum << endl;
                if (status >= 200 && status < 300)
                    httprep.successHttp++;
                else
                    httprep.failedHttp++;
                pendingHttpRequests.erase(seqNum);
                httprep.failedHttp--; // we counted pending as failed so we need failed -1
            }
            else
            {
                // Response without matching request
                if (status >= 200 && status < 300)
                    pendingHttpResponses[seqNum] = 1;
                else
                    pendingHttpResponses[seqNum] = -1;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing HTTP Binary: " << e.what() << std::endl;
    }
}
Binary HttpReporter::extractHttpPayload(const Binary &bin)
{
    if (!bin.data || bin.length < 14 + 20 + 20) // eth + min ip + min tcp
        throw std::runtime_error("Packet too short for HTTP");

    const uint8_t *ptr = bin.data;
    size_t len = bin.length;

    // --- eth ---
    if (len < 14)
        throw std::runtime_error("Too short for Ethernet");
    uint16_t ethType = (ptr[12] << 8) | ptr[13];
    ptr += 14;
    len -= 14;

    // --- ip ---
    if (ethType == 0x0800) // IPv4
    {
        if (len < 20)
            throw std::runtime_error("Too short for IPv4");
        uint8_t ihl = ptr[0] & 0x0F; // IHL in 32-bit words
        size_t ipHeaderLen = ihl * 4;
        if (len < ipHeaderLen)
            throw std::runtime_error("IPv4 header truncated");
        ptr += ipHeaderLen;
        len -= ipHeaderLen;
    }
    else if (ethType == 0x86DD) // IPv6
    {
        if (len < 40)
            throw std::runtime_error("Too short for IPv6");
        ptr += 40;
        len -= 40;
    }
    else
    {
        throw std::runtime_error("Unsupported EtherType for HTTP");
    }

    // --- tcp ---
    if (len < 20)
        throw std::runtime_error("Too short for TCP");
    uint8_t dataOffset = (ptr[12] >> 4) & 0x0F; // upper 4 bits = header length in 32-bit words
    size_t tcpHeaderLen = dataOffset * 4;
    if (len < tcpHeaderLen)
        throw std::runtime_error("TCP header truncated");
    ptr += tcpHeaderLen;
    len -= tcpHeaderLen;

    // --- http ---
    Binary httpPayload;
    httpPayload.data = nullptr;
    httpPayload.length = 0;

    if (len > 0)
    {
        httpPayload.data = new uint8_t[len];
        std::memcpy(httpPayload.data, ptr, len);
        httpPayload.length = len;
    }

    return httpPayload;
}

bool HttpReporter::isSuccessHttpResponse(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    if (!httpRes)
        return false;

    int status = httpRes->getFirstLine()->getStatusCode();
    return status >= 200 && status < 300;
}

std::string HttpReporter::httpMethod(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto httpReq = packet.getLayerOfType<pcpp::HttpRequestLayer>();
    if (!httpReq)
        return "";

    auto methodEnum = httpReq->getFirstLine()->getMethod();
    switch (methodEnum) {
        case pcpp::HttpRequestLayer::HttpGET: return "GET";
        case pcpp::HttpRequestLayer::HttpPOST: return "POST";
        case pcpp::HttpRequestLayer::HttpHEAD: return "HEAD";
        case pcpp::HttpRequestLayer::HttpPUT: return "PUT";
        case pcpp::HttpRequestLayer::HttpDELETE: return "DELETE";
        case pcpp::HttpRequestLayer::HttpOPTIONS: return "OPTIONS";
        case pcpp::HttpRequestLayer::HttpTRACE: return "TRACE";
        case pcpp::HttpRequestLayer::HttpCONNECT: return "CONNECT";
        case pcpp::HttpRequestLayer::HttpPATCH: return "PATCH";
        default: return "";
    }
}

int HttpReporter::httpStatusCode(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    if (!httpRes)
        return -1;

    return httpRes->getFirstLine()->getStatusCode();
}

bool HttpReporter::isHttpResponse(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    return httpRes != nullptr;
}