#include "DnsAnalyzer.h"
#include <stdexcept>
#include <cstring>

// first 2 bytes are transaction id
uint16_t DnsReporter::transactionID(const Binary& bin) {
    if (bin.length < 2) {
        throw std::runtime_error("Binary too short for DNS ID");
    }
    return (bin.data[0] << 8) | bin.data[1];
}

// check qr (bit 15 of 3rd/4th byte)
bool DnsReporter::isResponse(const Binary& bin) {
    if (bin.length < 4) {
        throw std::runtime_error("Binary too short for DNS flags");
    }
    uint16_t flags = (bin.data[2] << 8) | bin.data[3];
    return (flags & 0x8000) != 0; /* qr = 1 : response 
                                     the 15th bit is qr bit*/
}

void DnsReporter::addBinary(const Binary& bin) {
    try {
        uint16_t txid = transactionID(bin);
        if (isResponse(bin)) {
            auto it = pendingRequests.find(txid);
            if (it != pendingRequests.end()) {//res
                // found matching request so form transaction
                DnsTransaction tx{it->second, bin};
                transactions.push_back(tx);
                pendingRequests.erase(it);
            } else {
                // no request found yet so ignore or store separately
            }
        } else { //req
            pendingRequests[txid] = bin;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing Binary: " << e.what() << std::endl;
    }
}

void DnsReporter::addDnsTransaction(const DnsTransaction& tx) {
    transactions.push_back(tx);
}

bool DnsReporter::isSuccessResponse(const Binary& bin) const {
    if (bin.length < 4) {
        throw std::runtime_error("Binary too short for DNS flags");
    }
    uint16_t flags = (bin.data[2] << 8) | bin.data[3];
    uint8_t rcode = flags & 0x000F; // last 4 bits
    return rcode == 0; // 0 = success
}

void DnsReporter::getReport() const {
    size_t total = transactions.size();
    size_t success = 0;
    for (const auto& tx : transactions) {
        if (tx.response.data != nullptr && tx.response.length > 0) {
            if (isSuccessResponse(tx.response)) {
            success++;
            }
        }
    }
    std::cout << "Total transactions: " << total << "\n";
    std::cout << "Successful transactions: " << success << "\n";
    std::cout << "Success rate: "
              << (total > 0 ? (100.0 * success / total) : 0.0)
              << "%\n";
}
