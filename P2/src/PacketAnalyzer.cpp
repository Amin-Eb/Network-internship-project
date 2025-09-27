#include "PacketAnalyzer.h"
#include <stdexcept>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdexcept>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <cstring>
#include <pcapplusplus/TcpLayer.h>
using namespace std;

Binary Reporter::extractDnsPayload(const Binary &bin)
{
    if (!bin.data || bin.length < 14 + 8) // minimum: ethernet + UDP
        throw std::runtime_error("Packet too short");

    const uint8_t *ptr = bin.data;
    size_t len = bin.length;

    // --- eth ---
    if (len < 14)
        throw std::runtime_error("Too short for Ethernet header");
    uint16_t ethType = (ptr[12] << 8) | ptr[13]; // bytes 12-13
    ptr += 14;
    len -= 14;

    // --- ip ---
    if (ethType == 0x0800)
    { // IPv4
        if (len < 20)
            throw std::runtime_error("Too short for IPv4 header");
        uint8_t ihl = ptr[0] & 0x0F; // header length in 32-bit words
        size_t ipHeaderLen = ihl * 4;
        if (len < ipHeaderLen)
            throw std::runtime_error("IPv4 header truncated");
        ptr += ipHeaderLen;
        len -= ipHeaderLen;
    }
    else if (ethType == 0x86DD)
    { // IPv6
        if (len < 40)
            throw std::runtime_error("Too short for IPv6 header");
        ptr += 40;
        len -= 40;
    }
    else
    {
        throw std::runtime_error("Unsupported EtherType");
    }

    // --- udp ---
    if (len < 8)
        throw std::runtime_error("Too short for UDP header");
    ptr += 8;
    len -= 8;

    // --- dns ---
    Binary dnsPayload;
    dnsPayload.data = const_cast<uint8_t *>(ptr); // points inside original packet
    dnsPayload.length = len;
    return dnsPayload;
}

uint16_t Reporter::DnstransactionID(const Binary &bin)
{
    Binary dnsPayload = extractDnsPayload(bin);

    if (dnsPayload.length < 2 || dnsPayload.data == nullptr)
    {
        throw std::runtime_error("DNS payload too short for transaction ID");
    }

    // 0-1 bytes
    uint16_t txid = (dnsPayload.data[0] << 8) | dnsPayload.data[1];
    return txid;
}

bool Reporter::isDnsResponse(const Binary &bin)
{
    Binary dnsPayload = extractDnsPayload(bin);

    if (dnsPayload.length < 4 || dnsPayload.data == nullptr)
    {
        throw std::runtime_error("DNS payload too short for flags");
    }

    // Flags are bytes 2 and 3 of DNS payload
    uint16_t flags = (dnsPayload.data[2] << 8) | dnsPayload.data[3];

    // qr is 15th, the leftmost bit
    return (flags & 0x8000) != 0; // 1 = response, 0 = query
}

bool Reporter::isSuccessDnsResponse(const Binary &bin)
{
    Binary dnsPayload = extractDnsPayload(bin);

    if (dnsPayload.length < 4 || dnsPayload.data == nullptr)
    {
        throw std::runtime_error("DNS payload too short for flags");
    }

    // 2-3 bytes
    uint16_t flags = (dnsPayload.data[2] << 8) | dnsPayload.data[3];

    // rcode is the last 4 bits of flags
    uint8_t rcode = flags & 0x000F;

    return rcode == 0; // 0 = successful response
}
void Reporter::addDnsBinary(const Binary &bin)
{
    try
    {
        Binary dnsPayload = extractDnsPayload(bin);
        if (dnsPayload.length == 0 || dnsPayload.data == nullptr)
            return;
        // packet is dns
        uint16_t txid = DnstransactionID(bin);
        // cout << "id is : " << std::hex << txid << endl;
        if (isDnsResponse(bin))
        { // res
            auto it = pendingRequests.find(txid);
            if (it != pendingRequests.end())
            {
                // found matching request, form transaction
                if (isSuccessDnsResponse(bin))
                {
                    rep.successDns++;
                }
                else
                {
                    rep.failedDns++;
                }
                pendingRequests.erase(it);
                rep.totalDns++;
            }
            rep.recieved++;
        }
        else
        { // request
            pendingRequests[txid] = bin;
            rep.recieved++;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing Binary: " << e.what() << std::endl;
    }
}

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
            rep.recieved++;
            // Keep request until we see a response
            if (seqNum != 0)
                pendingHttpRequests[seqNum] = bin;
        }
        else if (httpRes)
        {
            rep.totalHttp++;
            rep.recieved++;

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
        return 0;

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

bool Reporter::isSip(const Binary &bin){
    return 0;
}

bool Reporter::isSipResponse(const Binary &bin){
    return 0;
}

bool Reporter::isSuccessSipResponse(const Binary &bin){
    return 0;
}

int Reporter::sipStatusCode(const Binary &bin){
    return 0;
}

void Reporter::addSipBinary(const Binary &bin){
    // TODO
}


void Reporter::addBinary(const Binary &bin)
{
    int type = getPacketType(bin);
    if (type == DNS)
    {
        addDnsBinary(bin);
    }
    else if (type == HTTP)
    {
        addHttpBinary(bin);
    }
}
Report Reporter::getReport() const
{
    return rep;
}
