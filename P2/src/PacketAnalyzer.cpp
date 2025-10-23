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
#include <mutex>
using namespace std;

void Reporter::addBinary(const Binary &bin)
{
    rep.recieved ++;
    int type = utils.getPacketType(bin);
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
