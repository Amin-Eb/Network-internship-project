#include "DnsAnalyzer.h"
#include <stdexcept>
#include <iostream>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <arpa/inet.h>

uint16_t DnsReporter::transactionID(const Binary& bin) {
    if (bin.length == 0 || bin.data == nullptr)
        throw std::runtime_error("Empty packet");

    pcpp::RawPacket rawPacket((const uint8_t*)bin.data, bin.length, timeval(), false);
    pcpp::Packet packet(&rawPacket);

    auto dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
    if (!dnsLayer)
        throw std::runtime_error("No DNS layer found id");

    // convert network byte order to host byte order
    return ntohs(dnsLayer->getDnsHeader()->transactionID);
}

bool DnsReporter::isResponse(const Binary& bin) {
    if (bin.length == 0 || bin.data == nullptr)
        throw std::runtime_error("Empty packet");

    pcpp::RawPacket rawPacket((const uint8_t*)bin.data, bin.length, timeval(), false);
    pcpp::Packet packet(&rawPacket);

    auto dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
    if (!dnsLayer)
        throw std::runtime_error("No DNS layer found");

    // qr flag: 0 = query, 1 = response
    return dnsLayer->getDnsHeader()->queryOrResponse == 1;
}

bool DnsReporter::isSuccessResponse(const Binary& bin) {
    if (bin.length == 0 || bin.data == nullptr)
        throw std::runtime_error("Empty packet");

    pcpp::RawPacket rawPacket((const uint8_t*)bin.data, bin.length, timeval(), false);
    pcpp::Packet packet(&rawPacket);

    auto dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
    if (!dnsLayer)
        return false;

    return dnsLayer->getDnsHeader()->responseCode == 0; // 0 = success
}

void DnsReporter::addBinary(const Binary& bin) {
    try {
        pcpp::RawPacket rawPacket((const uint8_t*)bin.data, bin.length, timeval(), false);
        pcpp::Packet packet(&rawPacket);
        auto dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
        if (!dnsLayer) return; // skip non-DNS
        uint16_t txid = transactionID(bin);

        if (isResponse(bin)) { //res
            auto it = pendingRequests.find(txid);
            if (it != pendingRequests.end()) {
                // found matching request, form transaction
                if(isSuccessResponse(bin)){
                    rep.success++;
                } else {
                    rep.failed++;
                }
                pendingRequests.erase(it);
                rep.total++;
            }
            rep.recieved++;
        } else { // request
            pendingRequests[txid] = bin;
            rep.recieved++;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error parsing Binary: " << e.what() << std::endl;
    }
}
Report DnsReporter::getReport() const {
    return rep; 
}
