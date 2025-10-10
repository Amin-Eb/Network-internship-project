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
#include <ndpi/ndpi_api.h>

using namespace std;

static ndpi_detection_module_struct* g_ndpi_mod = nullptr;
static bool ndpi_init_flag;


static void initNdpiOnce() {
    ndpi_init_flag = 1;
    g_ndpi_mod = ndpi_init_detection_module(NULL);
    if (!g_ndpi_mod) 
    {
        cerr << "ndpi falied!" << endl;
        return;
    }
    ndpi_load_protocols_file(g_ndpi_mod, NULL);  // load default protocols
    ndpi_finalize_initialization(g_ndpi_mod);
}
int Reporter::getPacketType(const Binary &bin) {
    if (!bin.data || bin.length < 1)
        return NONE;

    if(!ndpi_init_flag) initNdpiOnce();
    if (!g_ndpi_mod)
        return NONE;

    const uint8_t* data = bin.data;
    size_t len = bin.length;

    // ---  Ethernet/IP detection ---
    uint16_t ethType = (data[12] << 8) | data[13];
    size_t ipOffset = 0;
    if (ethType == 0x0800 || ethType == 0x86DD) { // IPv4 or IPv6
        ipOffset = 14; // skip Ethernet header because ndpi doesnt work with it and no result
        ethType = ntohs(ethType);
    } else if (data[0] == 0x45 || data[0] == 0x60) {
        ipOffset = 0;
    } else {
        return NONE; // unknown type
    }

    if (len <= ipOffset)
        return NONE;

    const uint8_t* ipPacket = data + ipOffset; // move pointer after eth part
    size_t ipLen = len - ipOffset;

    struct ndpi_flow_struct flow{};
    memset(&flow, 0, sizeof(flow));

    struct ndpi_proto proto = ndpi_detection_process_packet(
        g_ndpi_mod,
        &flow,
        (uint8_t*)ipPacket,
        ipLen,
        0,
        nullptr
    );

    uint16_t detected = (proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
                            ? proto.proto.app_protocol
                            : proto.proto.master_protocol;
    switch (detected) {
        case NDPI_PROTOCOL_MDNS:
            return DNS;
        case NDPI_PROTOCOL_DNS: 
            return DNS;
        case NDPI_PROTOCOL_HTTP:
            return HTTP;
        case NDPI_PROTOCOL_HTTP_CONNECT:
            return HTTP;
        case NDPI_PROTOCOL_HTTP_PROXY:
            return HTTP;
        case NDPI_PROTOCOL_SIP: 
            return SIP;  
        default: return NONE;
    }
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
