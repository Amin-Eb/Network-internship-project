#include "DnsAnalyzer.h"
#include <stdexcept>
#include <cstring>

// Extract DNS Transaction ID (first 2 bytes)
uint16_t DnsReporter::extractTransactionID(const Binary& bin) {
    if (bin.length < 2) {
        throw std::runtime_error("Binary too short for DNS ID");
    }
    return (bin.data[0] << 8) | bin.data[1];
}

// Check QR flag (bit 15 of 3rd/4th byte)
bool DnsReporter::isResponse(const Binary& bin) {
    if (bin.length < 4) {
        throw std::runtime_error("Binary too short for DNS flags");
    }
    uint16_t flags = (bin.data[2] << 8) | bin.data[3];
    return (flags & 0x8000) != 0; // QR = 1 → response
}

void DnsReporter::addBinary(const Binary& bin) {
    try {
        uint16_t txid = extractTransactionID(bin);
        if (isResponse(bin)) {
            // Response
            auto it = pendingRequests.find(txid);
            if (it != pendingRequests.end()) {
                // Found matching request → form transaction
                DnsTransaction tx{it->second, bin};
                transactions.push_back(tx);
                pendingRequests.erase(it);
            } else {
                // No request found yet → ignore or store separately
            }
        } else {
            // Request
            pendingRequests[txid] = bin;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing Binary: " << e.what() << std::endl;
    }
}

void DnsReporter::addDnsTransaction(const DnsTransaction& tx) {
    transactions.push_back(tx);
}

void DnsReporter::getReport() const {
    size_t total = transactions.size();
    size_t success = 0;
    for (const auto& tx : transactions) {
        if (tx.response.data != nullptr && tx.response.length > 0) {
            success++;
        }
    }
    std::cout << "Total transactions: " << total << "\n";
    std::cout << "Successful transactions: " << success << "\n";
    std::cout << "Success rate: "
              << (total > 0 ? (100.0 * success / total) : 0.0)
              << "%\n";
}
