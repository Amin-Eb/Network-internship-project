#pragma once
#include "PacketBinary.h"
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <netinet/in.h>
#include <cstring>
#include <string>

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

    bool operator==(const FlowKey &o) const {
        return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport;
    }
};

// hash for flowKey
struct FlowKeyHash {
    size_t operator()(const FlowKey &k) const noexcept {
        return hash<string>()(k.src) ^ (hash<string>()(k.dst) << 1)
             ^ (hash<uint16_t>()(k.sport) << 2) ^ (hash<uint16_t>()(k.dport) << 3);
    }
};

class TcpReporter
{
public:
    explicit TcpReporter(TcpReport& sharedReport, string client)
        : tcprep(sharedReport) {this->client = client;}

    void addTcpBinary(const Binary &bin);
    TcpReport& getTcpReport() { return tcprep; }

private:
    TcpReport& tcprep;
    string client;

    struct FlowMeta {
        uint8_t stateMask = STATE_NONE;
    }; // TODO : defined as struct not simple integer, meybe we added things about time further

    unordered_map<FlowKey, FlowMeta, FlowKeyHash> flows;

    bool extractIPv4TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen);
    bool extractIPv6TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen);
    void handleTcpFlags(const FlowKey &key, uint8_t flags, size_t payloadLen);
};
