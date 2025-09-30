#include "SipReporter.h"
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/SipLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>

Binary SipReporter::extractSipPayload(const Binary &bin)
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

bool SipReporter::isSip(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto *sipReq = packet.getLayerOfType<pcpp::SipRequestLayer>();
    auto *sipRes = packet.getLayerOfType<pcpp::SipResponseLayer>();

    return sipReq != nullptr || sipRes != nullptr;
}

bool SipReporter::isSipResponse(const Binary &bin)
{
    timeval tv{};
    pcpp::RawPacket rawPacket((const uint8_t *)bin.data, bin.length, tv, false);
    pcpp::Packet packet(&rawPacket);

    auto *sipRes = packet.getLayerOfType<pcpp::SipResponseLayer>();
    return sipRes != nullptr;
}

bool SipReporter::isSuccessSipResponse(const Binary &bin)
{
    int code = sipStatusCode(bin);
    return (code >= 200 && code < 300);
}

int SipReporter::sipStatusCode(const Binary &bin)
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
std::string SipReporter::extractSipCallId(const Binary &bin) {
    auto* data = bin.data;
    auto len = bin.length;
    std::string payload(reinterpret_cast<const char*>(data), len);
    auto pos = payload.find("Call-ID:");
    if (pos == std::string::npos) return {};
    pos += strlen("Call-ID:");
    // skip spaces
    while (pos < payload.size() && isspace((unsigned char)payload[pos])) ++pos;
    auto end = payload.find_first_of("\r\n", pos);
    if (end == std::string::npos) end = payload.size();
    std::string callid = payload.substr(pos, end - pos);
    // trim...
    return callid;
}

void SipReporter::addSipBinary(const Binary &bin)
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
            sipRequests.insert(extractSipCallId(bin));
            siprep.totalSip++;
            siprep.failedSip++;
        }
        else if (sipRes)
        {
            int code = sipStatusCode(bin);
            
            if (code >= 200 && code < 300) 
            {
                if(sipRequests.find(extractSipCallId(bin)) != sipRequests.end()) 
                {
                    siprep.successSip++;
                    sipRequests.erase(extractSipCallId(bin));
                    siprep.failedSip--;
                    //cout << extractSipCallId(bin) << " ok " << endl;
                }
            }
            else if (code >= 400 && code <= 608) 
            { // failure (>=400 are errors)
                if(sipRequests.find(extractSipCallId(bin)) != sipRequests.end()) 
                {
                    siprep.failedSip++;
                    sipRequests.erase(extractSipCallId(bin));
                    siprep.failedSip--;
                   // cout << extractSipCallId(bin) << " fail " << endl;
                }
            }

        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error parsing SIP Binary: " << e.what() << std::endl;
    }
}