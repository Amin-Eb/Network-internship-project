#include "PacketAnalyzer.h"
#include "DnsReporter.h"
#include "HttpReporter.h"
#include "SipReporter.h"
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

void Reporter::addBinary(const Binary &bin)
{
    rep.recieved ++;
    int type = getPacketType(bin);
    if (type == DNS)
    {
        dnsreporter.addDnsBinary(bin);
        rep.dnsreport = &dnsreporter.getDnsReport();
    }
    else if (type == HTTP)
    {
        httpreporter.addHttpBinary(bin);
        rep.httpreport = &httpreporter.getHttpReport();
    }
    else if (type == SIP)
    {
        sipreporter.addSipBinary(bin);
        rep.sipreport = &sipreporter.getSipReport();
    }
}
Report& Reporter::getReport() const
{
    return rep;
}
