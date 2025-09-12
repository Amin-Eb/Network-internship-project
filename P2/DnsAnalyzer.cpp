#include "DnsAnalyzer.h"
#include <iostream>

using namespace std;

DnsStats processPcap(const std::string& filename) {
    DnsStats stats;
    
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename);
    if (!reader) {
        std::cerr << "Error: unsupported file type or cannot create reader for " << filename << "\n";
        return stats;
    }

    if (!reader->open()) {
        std::cerr << "Error: could not open pcap file " << filename << "\n";
        stats.errorcode = -1;
        delete reader;
        return stats;
    }

    std::set<DnsKey, DnsKeyCmp> requests;
    std::set<DnsKey, DnsKeyCmp> answers;

    int counter = 0;
    stats.errorcode = -2;
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        #ifndef FIRST_PACKET
            #define FIRST_PACKET
            stats.errorcode = 0;
        #endif
        pcpp::Packet parsed(&rawPacket);
        counter++;

        auto* dns = parsed.getLayerOfType<pcpp::DnsLayer>();
        if (!dns) continue;

        std::string srcIp = "0.0.0.0";
        std::string dstIp = "0.0.0.0";

        auto* ip = parsed.getLayerOfType<pcpp::IPv4Layer>();
        if (ip) {
            srcIp = ip->getSrcIPv4Address().toString();
            dstIp = ip->getDstIPv4Address().toString();
        }

        uint16_t id = dns->getDnsHeader()->transactionID;
        bool isResponse = dns->getDnsHeader()->queryOrResponse == 1;

        DnsKey key{id, srcIp, dstIp};

        if (!isResponse) {
            requests.insert(key);
        } else {
            answers.insert(key);

            DnsKey reqKey{id, dstIp, srcIp};
            auto it = requests.find(reqKey);
            if (it != requests.end()) {
                if (dns->getDnsHeader()->responseCode == 0) stats.successful++;
                else {
                    stats.unsuccessful++;
                    cout << "WRONG :: " << dns->getDnsHeader()->transactionID << endl;
                }
                requests.erase(it);
                answers.erase(key);
            }
        }
    }

    reader->close();
    delete reader;

    return stats;
}
