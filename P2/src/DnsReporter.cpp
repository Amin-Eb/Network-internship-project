#include "DnsReporter.h"
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/RawPacket.h>

using namespace std;

Binary DnsReporter::extractDnsPayload(const Binary &bin)
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

uint16_t DnsReporter::DnstransactionID(const Binary &bin)
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

bool DnsReporter::isDnsResponse(const Binary &bin)
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

bool DnsReporter::isSuccessDnsResponse(const Binary &bin)
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
void DnsReporter::addDnsBinary(const Binary &bin)
{
    try
    {
        Binary dnsPayload = extractDnsPayload(bin);
        if (dnsPayload.length == 0 || dnsPayload.data == nullptr)
            return;
        // packet is dns
        uint16_t txid = DnstransactionID(bin);
        if(txid == 0) return;
        if (isDnsResponse(bin))
        { // res
            auto it = pendingDnsRequests.find(txid);
            if (it != pendingDnsRequests.end())
            {
                dnsrep.failedDns --;
                // found matching request, form transaction
                if (isSuccessDnsResponse(bin))
                {
                    dnsrep.successDns++;
                }
                else
                {
                    dnsrep.failedDns++;
                }
                pendingDnsRequests.erase(it);
                dnsrep.totalDns++;
            }
        }
        else
        { // request
            dnsrep.failedDns++;
            pendingDnsRequests.insert(txid);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing Binary: " << e.what() << std::endl;
    }
}