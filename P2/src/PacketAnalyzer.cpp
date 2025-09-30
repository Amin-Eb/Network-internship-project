#include "PacketAnalyzer.h"
#include "DnsReporter.h"
#include <stdexcept>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <stdexcept>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/SipLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>


using namespace std;

void Reporter::addHttpBinary(const Binary &bin)
{
    try
    {
        timeval tv{};
        pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
        pcpp::Packet packet(&rawPacket);

        auto tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        uint32_t seqNum = 0;
        if (tcpLayer)
            seqNum = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);

        auto httpReq = packet.getLayerOfType<pcpp::HttpRequestLayer>();
        auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();

        if (httpReq)
        {
            rep.totalHttp++;
            // Keep request until we see a response
            if (seqNum != 0){
                pendingHttpRequests[seqNum] = bin;
            }

        }
        else if (httpRes)
        { 
            rep.totalHttp++;

            int status = httpRes->getFirstLine()->getStatusCode();

            if (seqNum != 0 && pendingHttpRequests.count(seqNum))
            {
                if (status >= 200 && status < 300)
                    rep.successHttp++;
                else
                    rep.failedHttp++;
                pendingHttpRequests.erase(seqNum);
            }
            else
            {
                // Response without matching request
                if (status >= 200 && status < 300)
                    rep.successHttp++;
                else
                    rep.failedHttp++;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing HTTP Binary: " << e.what() << std::endl;
    }
}

int Reporter::getPacketType(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    // DNS?
    auto dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
    if (dnsLayer != nullptr)
    {
        return DNS;
    }

    // HTTP? (pcap++ has HttpRequestLayer / HttpResponseLayer)
    auto httpReq = packet.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpReq != nullptr)
    {
        return HTTP;
    }
    auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    if (httpRes != nullptr)
    {
        return HTTP;
    }
    // SIP ? both res/req will be included
    auto* sipRes = packet.getLayerOfType<pcpp::SipResponseLayer>();
    if (sipRes != nullptr)
    {
        return SIP;
    }
    auto* sipReq = packet.getLayerOfType<pcpp::SipRequestLayer>();
    if (sipReq != nullptr)
    {   
        return SIP;
    }   
    return NONE;
}
Binary Reporter::extractHttpPayload(const Binary &bin)
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

bool Reporter::isSuccessHttpResponse(const Binary &bin)
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

std::string Reporter::httpMethod(const Binary &bin)
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

int Reporter::httpStatusCode(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    if (!httpRes)
        return -1;

    return httpRes->getFirstLine()->getStatusCode();
}

bool Reporter::isHttpResponse(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto httpRes = packet.getLayerOfType<pcpp::HttpResponseLayer>();
    return httpRes != nullptr;
}

Binary Reporter::extractSipPayload(const Binary &bin)
{
    if (!bin.data || bin.length < 14 + 20 + 8) // eth + min ip + min udp
        throw std::runtime_error("Packet too short for SIP");

    const uint8_t *ptr = bin.data;
    size_t len = bin.length;

    // --- Ethernet ---
    if (len < 14)
        throw std::runtime_error("Too short for Ethernet");
    uint16_t ethType = (ptr[12] << 8) | ptr[13];
    ptr += 14;
    len -= 14;

    // --- IP ---
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
        throw std::runtime_error("Unsupported EtherType for SIP");
    }

    // --- UDP ---
    if (len < 8)
        throw std::runtime_error("Too short for UDP");
    ptr += 8;
    len -= 8;

    // --- SIP ---
    Binary sipPayload;
    sipPayload.data = nullptr;
    sipPayload.length = 0;

    if (len > 0)
    {
        sipPayload.data = new uint8_t[len];
        std::memcpy(sipPayload.data, ptr, len);
        sipPayload.length = len;
    }

    return sipPayload;
}

bool Reporter::isSip(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto *sipReq = packet.getLayerOfType<pcpp::SipRequestLayer>();
    auto *sipRes = packet.getLayerOfType<pcpp::SipResponseLayer>();

    return sipReq != nullptr || sipRes != nullptr;
}

bool Reporter::isSipResponse(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto *sipRes = packet.getLayerOfType<pcpp::SipResponseLayer>();
    return sipRes != nullptr;
}

bool Reporter::isSuccessSipResponse(const Binary &bin)
{
    int code = sipStatusCode(bin);
    return (code >= 200 && code < 300);
}

int Reporter::sipStatusCode(const Binary &bin)
{
    Binary sipPayload = extractSipPayload(bin);
    if (!sipPayload.data || sipPayload.length < 12)
        throw std::runtime_error("SIP payload too short for status code");

   // cout << sipPayload.data[8] << "wed" << endl;
    // Bytes 10-12 = status code (ASCII decimal)
    char codeStr[4] = {0};
    codeStr[0] = sipPayload.data[8];   
    codeStr[1] = sipPayload.data[9];  
    codeStr[2] = sipPayload.data[10]; 
    codeStr[3] = '\0';

    return std::atoi(codeStr);
}

void Reporter::addSipBinary(const Binary &bin)
{
    try
    {
        timeval tv{};
        pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
        pcpp::Packet packet(&rawPacket);

        auto *sipReq = packet.getLayerOfType<pcpp::SipRequestLayer>();
        auto *sipRes = packet.getLayerOfType<pcpp::SipResponseLayer>();

        if (sipReq)
        {
            // Start of a SIP transaction (INVITE, REGISTER, etc.)
            rep.totalSip++;
        }
        else if (sipRes)
        {
            int code = sipStatusCode(bin);

            if (code >= 200 && code < 300)
                rep.successSip++;
            else if (code >= 300) // failure (>=300 are errors)
                rep.failedSip++;

        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing SIP Binary: " << e.what() << std::endl;
    }
}


void Reporter::addBinary(const Binary &bin)
{
    rep.recieved ++;
    int type = getPacketType(bin);
    if (type == DNS)
    {
        dnsreporter.addDnsBinary(bin);
        rep.dnsreport = dnsreporter.getDnsReport();
    }
    else if (type == HTTP)
    {
        addHttpBinary(bin);
    }
    else if (type == SIP)
    {
        addSipBinary(bin);
    }
}
Report Reporter::getReport() const
{
    return rep;
}
