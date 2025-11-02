#include "TcpReporter.h"
#include <arpa/inet.h>
#include <iostream>
#include "PacketUtils.h"
#include "PacketBinary.h"
#include <algorithm>
#include <vector>
#include "TcpNeeds.h"
#include "Constants.h"

enum {
    IPV4 = 0x0800,
    IPV6 = 0x86dd,
};

bool TcpReporter::extractTcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen) {
    if (len < ETH_HEADER_LEN + IPV4_HEADER_LEN) 
        return false;
        
    const uint16_t IpV = (data[12] << 8) | (data[13]);
    uint32_t offset = 0;
    if(IpV == IPV4) 
        offset = 23;
    else if(IpV == IPV6) 
        offset = 20;
    else return false;
    if(static_cast<int>(data[offset]) != 6) // not TCP
        return false;

    const uint8_t *ipHeader = data + ETH_HEADER_LEN;
    tcpPtr = ipHeader + (IpV == IPV4? IPV4_HEADER_LEN : IPV6_HEADER_LEN);
    if(IpV == IPV6) {
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipHeader + 8, src, sizeof(src));
        inet_ntop(AF_INET6, ipHeader + 24, dst, sizeof(dst));
        key.src = src;
        key.dst = dst;
    }
    else {
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipHeader + 12, src, sizeof(src));
        inet_ntop(AF_INET, ipHeader + 16, dst, sizeof(dst));
        key.src = src;
        key.dst = dst;
    }

    if (len < (tcpPtr - data) + TCP_HEADER_MIN_LEN) return false;
    key.sport = ntohs(*(uint16_t*)tcpPtr);
    key.dport = ntohs(*(uint16_t*)(tcpPtr + 2));

    size_t totalLen = ntohs(*(uint16_t*)(ipHeader + 2));
    tcpLen = totalLen - (IpV == IPV4? ETH_HEADER_LEN + IPV4_HEADER_LEN : 0);

    return true;
} 
bool TcpReporter::extractIPv4TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen) {
    if (len < ETH_HEADER_LEN + IPV4_HEADER_LEN) return false;

    const uint8_t *ipHeader = data + ETH_HEADER_LEN;
    uint8_t ihl = (ipHeader[0] & 0x0F) * 4;
    uint8_t proto = ipHeader[9];
    if (proto != 6) return false; // not TCP

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipHeader + 12, src, sizeof(src));
    inet_ntop(AF_INET, ipHeader + 16, dst, sizeof(dst));
    key.src = src;
    key.dst = dst;

    tcpPtr = ipHeader + ihl;
    if (len < (tcpPtr - data) + TCP_HEADER_MIN_LEN) return false;

    key.sport = ntohs(*(uint16_t*)tcpPtr);
    key.dport = ntohs(*(uint16_t*)(tcpPtr + 2));

    size_t totalLen = ntohs(*(uint16_t*)(ipHeader + 2));
    tcpLen = totalLen - ihl;

    return true;
}

bool TcpReporter::extractIPv6TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen) {
    if (len < ETH_HEADER_LEN + IPV6_HEADER_LEN) return false;

    const uint8_t *ipHeader = data + ETH_HEADER_LEN;
    uint8_t nextHdr = ipHeader[6];
    if (nextHdr != 6) return false; // not TCP

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipHeader + 8, src, sizeof(src));
    inet_ntop(AF_INET6, ipHeader + 24, dst, sizeof(dst));
    key.src = src;
    key.dst = dst;

    tcpPtr = ipHeader + IPV6_HEADER_LEN;
    if (len < (tcpPtr - data) + TCP_HEADER_MIN_LEN) return false;

    key.sport = ntohs(*(uint16_t*)tcpPtr);
    key.dport = ntohs(*(uint16_t*)(tcpPtr + 2));
    tcpLen = ntohs(*(uint16_t*)(ipHeader + 4)); // payload length

    return true;
}

void TcpReporter::finalizeFlow(const FlowKey &key) {
    if (saveContent) {
        auto it = flow_data.find(key);
        if (it != flow_data.end()) {
            TcpFlow& flow = it->second;
            
            string filename = flow.first + "_" + to_string(flow.fport) + 
                            "_to_" + flow.second + "_" + to_string(flow.sport) + ".txt";
            
            // Find maximum file size needed
            size_t maxOffset = 0;
            for (const auto& [offset, payloadData] : flow.mp) {
                maxOffset = std::max(maxOffset, offset + payloadData.size());
            }
            // Create buffer and copy all payload data
            vector<uint8_t> buffer(maxOffset, 0);
            size_t totalBytes = 0;
            
            for (const auto& [offset, payloadData] : flow.mp) {
                if (!payloadData.empty() && offset + payloadData.size() <= buffer.size()) {
                    memcpy(buffer.data() + offset , payloadData.data(), payloadData.size());
                    totalBytes += payloadData.size();
                }
            }
            
            // Write to file
            FILE* file = fopen(filename.c_str(), "wb");
            if (file) {
                size_t written = fwrite(buffer.data(), 1, buffer.size(), file);
                fclose(file);
            } else {
                cerr << "Failed to open file: " << filename << endl;
            }
        }
    }
    flow_data.erase(key);
}
void TcpReporter::handleTcpFlags(const FlowKey &key, uint8_t flags, size_t payloadLen, const uint8_t* &tcpPtr) {
    FlowMeta &meta = flows[key];
    if (flags == 0x002) { // SYN
        if (!(meta.stateMask & STATE_SYN_SENT)) {
            meta.stateMask |= STATE_SYN_SENT;
            tcprep.totalConnections++;
            tcprep.openConnections++;
            TcpFlow flowd = TcpFlow();
            flowd.first = key.src;
            flowd.second = key.dst;
            flowd.fport = key.sport; // we consider src as first and dst as second
            flowd.sport = key.dport;

            memcpy(&flowd.first_seq, tcpPtr + 4, 4);
            flowd.first_seq = ntohl(flowd.first_seq); // first packet of flow seq number is important
            flow_data[key] = flowd;
        }
    }
    if (flags == 0x12) { // SYN + ACK
        meta.stateMask |= STATE_SYN_ACKED;
    }
    if (flags == 0x10) { // ACK
        if ((meta.stateMask & STATE_SYN_ACKED) && !(meta.stateMask & STATE_ESTABLISHED)) {
            meta.stateMask |= STATE_ESTABLISHED;
        }
    }
    if (flags == 0x010 || flags == 0x018) {// ACK or ACK + PSH
        if ((meta.stateMask & STATE_ESTABLISHED) && key.sport == flow_data[key].fport/*only from starter of communication to inside(our client)*/) {
            uint32_t seq;
            memcpy(&seq, tcpPtr + 4, 4);
            seq = ntohl(seq);
            uint8_t dataOffset = (tcpPtr[12] >> 4) * 4;  // This should be at least 20
            const uint8_t* payload = tcpPtr + dataOffset;
        
            size_t payloadLen = 0;
            if (PacketUtils::isIPv4(tcpPtr - ETH_HEADER_LEN - 20, ETH_HEADER_LEN + 20)) {
                const uint8_t* ipHeader = tcpPtr - 20;
                size_t totalLen = ntohs(*(uint16_t*)(ipHeader + 2));
                payloadLen = totalLen - 20 - dataOffset;
            }
            vector<uint8_t> payloadCopy(payload, payload + payloadLen);
            int32_t relative_seq = seq - flow_data[key].first_seq - 1;
            flow_data[key].mp[relative_seq] = payloadCopy;
        }
    }
    if (flags == 0x011) { // FIN + ACK
        if (meta.stateMask & STATE_ESTABLISHED) {
            meta.stateMask = 0;
            meta.stateMask |= STATE_FIN_SEEN;
            tcprep.normalClosed++;
            tcprep.openConnections--;
            finalizeFlow(key);
        }
    }
    if (flags == 0x04) { // RST
        meta.stateMask |= STATE_RST_SEEN;
        flow_data.erase(key);
        tcprep.failedHandshakes++;
        tcprep.openConnections--;
    }
}

void TcpReporter::addTcpBinary(const Binary &bin) {
    const uint8_t *data = bin.data;
    size_t len = bin.length;
    if (!data || len < ETH_HEADER_LEN + TCP_HEADER_MIN_LEN) return;

    FlowKey key;
    const uint8_t *tcpPtr = nullptr;
    size_t tcpLen = 0;

    if (!extractTcpInfo(data, len, key, tcpPtr, tcpLen)) 
        return;
    tcprep.totalTcpPackets++;
    if (key.src == client)
            tcprep.bytesUploaded += bin.length;
    else
        tcprep.bytesDownloaded += bin.length;
    uint8_t dataOffset = (tcpPtr[12] >> 4) * 4;
    uint8_t flags = tcpPtr[13];
    size_t payloadLen = tcpLen > dataOffset ? tcpLen - dataOffset : 0;

    handleTcpFlags(key, flags, payloadLen, tcpPtr);
}
