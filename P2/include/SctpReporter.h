#pragma once
#include "PacketBinary.h"
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <netinet/in.h>
#include <vector>
#include <map>
#include <cstring>
#include <string>
#include <set>
#include "Constants.h"
#include "SctpNeeds.h"

using namespace std;

struct SctpReport {
    atomic<int> totalSctpPackets{0};
    atomic<int> openAssociations{0};
    atomic<int> totalAssociations{0};
    atomic<int> failedAssociations{0};
    atomic<long long> bytesUploaded{0};
    atomic<long long> bytesDownloaded{0};
    atomic<int> normalClosed{0};
};

struct FlowKey {
    string src;
    string dst;
    uint16_t sport;
    uint16_t dport;

    bool operator==(const FlowKey &o) const {// is bidirectional, from same (source, dest) no matters source port and dest port permutations
        return src == o.src && dst == o.dst && 
                ((sport == o.sport && dport == o.dport) || (sport == o.dport && dport == o.sport));
                
    }
    bool operator<(const FlowKey &o) const {
        if (src != o.src) return src < o.src;
        if (dst != o.dst) return dst < o.dst;
        if (sport != o.sport) return sport < o.sport;
        return dport < o.dport;
    }
};

// hash for flowKey
struct FlowKeyHash {
    size_t operator()(const FlowKey &k) const noexcept {
        uint16_t port1, port2;
        string src = min(k.src, k.dst);
        string dst = min(k.src, k.dst);
        port1 = min(k.sport, k.dport);
        port2 = max(k.sport, k.dport);
        return hash<string>()(src) ^ (hash<string>()(dst) << 1)
             ^ (hash<uint16_t>()(port1) << 2) ^ (hash<uint16_t>()(port2) << 3);
    }
};

struct SctpStream {
    uint16_t SSN = -1;
    map<uint32_t, vector<uint8_t>> dataMap;
};

//still using word flow instead of assosiation
struct SctpFlow {
    map<uint32_t, SctpStream> streams;
    string first;   
    string second;
    uint16_t fport = 0;
    uint16_t sport = 0;
    uint32_t srcVerif = 0;
    uint32_t dstVerif = 0;
};

class SctpReporter
{
public:
    explicit SctpReporter(SctpReport& sharedReport, string client)
        : tcprep(sharedReport) {this->clients.insert(client);} // force to have at least one client

    void addSctpBinary(const Binary &bin);
    SctpReport& getSctpReport() { return tcprep; }
    void setSaveContent(bool saveContent){this->saveContent = saveContent;}
    void addSctpClient(string client) { this->clients.insert(client); }
    
private:
    bool saveContent = 0;
    SctpReport& tcprep;
    set<string> clients;
    
    struct FlowMeta {
        uint8_t stateMask = STATE_NULL;
    }; // TODO : defined as struct not simple integer, meybe we added things about time further

    unordered_map<FlowKey, FlowMeta, FlowKeyHash> flows;
    unordered_map<FlowKey, SctpFlow, FlowKeyHash> flow_data;
    
    void finalizeFlow(const FlowKey &key);
    bool extractSctpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &sctpPtr, size_t &sctpLen);
    void handleSctpChunks(const FlowKey &key, size_t payloadLen,const uint8_t* &sctpPtr);
};

