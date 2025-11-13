#pragma once
#include "PacketBinary.h"
#include "TcpNeeds.h"
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <netinet/in.h>
#include <vector>
#include <map>
#include <cstring>
#include <string>
#include "Constants.h"


using namespace std;

struct TcpReport
{
    atomic<int> totalTcpPackets{0};
    atomic<int> openConnections{0};
    atomic<int> totalConnections{0};
    atomic<int> failedHandshakes{0};
    atomic<int> bytesUploaded{0};
    atomic<int> bytesDownloaded{0};
    atomic<int> normalClosed{0};
    atomic<int> timeouts{0};
};

// flow key
struct FlowKey {
    string src;
    string dst;
    uint16_t sport;
    uint16_t dport;

    bool operator==(const FlowKey &o) const {// is bidirectional, from same (source, dest) no matters source port and dest port permutations
        return (src == o.src && dst == o.dst &&
            sport == o.sport && dport == o.dport) ||
           (src == o.dst && dst == o.src &&
            sport == o.dport && dport == o.sport);
    }
    bool operator<(const FlowKey &o) const {
        if (src != o.src) return src < o.src;
        if (dst != o.dst) return dst < o.dst;
        if (sport != o.sport) return sport < o.sport;
        return dport < o.dport;
    }
};

struct TcpFlow {
    map<int,vector<uint8_t>> mp;
    string first;
    string second;
    uint16_t fport;
    uint16_t sport;
    uint32_t first_seq;
};

// hash for flowKey
struct FlowKeyHash {
    size_t operator()(const FlowKey &k) const noexcept {
        uint16_t port1, port2;
        string src = min(k.src, k.dst);
        string dst = max(k.src, k.dst);
        port1 = min(k.sport, k.dport);
        port2 = max(k.sport, k.dport);
        return hash<string>()(src) ^ (hash<string>()(dst) << 1)
             ^ (hash<uint16_t>()(port1) << 2) ^ (hash<uint16_t>()(port2) << 3);
    }
};

class TcpReporter
{
public:
    explicit TcpReporter(TcpReport& sharedReport, string client)
        : tcprep(sharedReport) {this->client = client;}

    void addTcpBinary(const Binary &bin);
    TcpReport& getTcpReport() { return tcprep; }
    void setSaveContent(bool saveContent){this->saveContent = saveContent;}
    
private:
    bool saveContent = 0;
    TcpReport& tcprep;
    string client;

    struct FlowMeta {
        uint8_t stateMask = STATE_NONE;
    }; // TODO : defined as struct not simple integer, meybe we added things about time further

    unordered_map<FlowKey, FlowMeta, FlowKeyHash> flows;
    unordered_map<FlowKey, TcpFlow, FlowKeyHash> flow_data;
    
    void finalizeFlow(const FlowKey &key);
    bool extractTcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen);
    bool extractIPv4TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen);
    bool extractIPv6TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen);
    void handleTcpFlags(const FlowKey &key, uint8_t flags, size_t payloadLen,const uint8_t* &tcpPtr);
};
