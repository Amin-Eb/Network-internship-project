#include "SctpReporter.h"
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <algorithm>

using namespace std;

void SctpReporter::finalizeFlow(const FlowKey &key) {
    auto itFlow = flow_data.find(key);
    if (itFlow == flow_data.end()) return;

    SctpFlow &flow = itFlow->second;
   
    if (saveContent) {
        for (auto &streamPair : flow.streams) {
            uint32_t ssn = streamPair.first;
            auto &sctpStream = streamPair.second;
            vector<uint32_t> tsns;
            tsns.reserve(sctpStream.dataMap.size());
            for (const auto &kv : sctpStream.dataMap) tsns.push_back(kv.first);
            sort(tsns.begin(), tsns.end());

            string filename = flow.first + "_" + to_string(flow.fport)
                            + "_and_" + flow.second + "_" + to_string(flow.sport)
                            + "_stream_" + to_string(ssn) + "download"+".bin";

            ofstream out(filename, ios::binary);
            if (!out) {
                cerr << "SCTP: failed to open " << filename << " for writing\n";
                continue;
            }
            for (uint32_t tsn : tsns) {
                const auto &vec = sctpStream.dataMap[tsn];
                if (!vec.empty()) out.write(reinterpret_cast<const char*>(vec.data()), vec.size());
            }
            out.close();
        }
    }

    flow_data.erase(itFlow);
    flows.erase(key);
}

bool SctpReporter::extractSctpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &sctpPtr, size_t &sctpLen) {
    if (!data || len < 14) return false;

    const uint8_t *eth = data;
    uint16_t ethType = (eth[12] << 8) | eth[13];

    const uint8_t *ipStart = data + 14;
    size_t ipLen = 0;
    uint8_t proto = 0;

    if (ethType == ETHERTYPE_IPV4) {
        if (len < 14 + 20) return false;
        uint8_t ihl = ipStart[0] & 0x0F;
        ipLen = ihl * 4;
        if (len < 14 + ipLen) return false;
        proto = ipStart[9];
        char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipStart + 12, srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET, ipStart + 16, dstbuf, sizeof(dstbuf));
        key.src = srcbuf;
        key.dst = dstbuf;
    } else if (ethType == ETHERTYPE_IPV6) {
        if (len < 14 + 40) return false;
        ipLen = 40;
        proto = ipStart[6]; 
        char srcbuf[INET6_ADDRSTRLEN], dstbuf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipStart + 8, srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET6, ipStart + 24, dstbuf, sizeof(dstbuf));
        key.src = srcbuf;
        key.dst = dstbuf;
    } else {
        return false;
    }

    if (proto != SCTP_NUMBER) return false;

    sctpPtr = ipStart + ipLen;
    if (sctpPtr < data) return false; 
    sctpLen = len - (sctpPtr - data);
    if (sctpLen < 12) return false; // SCTP common header = 12 bytes

    key.sport = ntohs(*(uint16_t*)sctpPtr);
    key.dport = ntohs(*(uint16_t*)(sctpPtr + 2));
    return true;
}

void SctpReporter::handleSctpChunks(const FlowKey &key, size_t payloadLen, const uint8_t* &sctpPtr) {
    if (!sctpPtr) return;
    const uint8_t* cur = sctpPtr + 12; // first chunk begins after common header
    const uint8_t* end = sctpPtr + payloadLen;
    if (cur >= end) return;
    while (cur + 4 <= end) {
        uint8_t chunkType = cur[0];
        uint8_t chunkFlags = cur[1];
        uint16_t chunkLen = (cur[2] << 8) | cur[3];
        if (chunkLen < 4) break; 
        const uint8_t* chunkData = cur + 4;
        const uint8_t* nextChunk = cur + ((chunkLen + 3) & ~3); // chunks are 4-byte aligned
        if (nextChunk > end) nextChunk = end; 
        FlowKeyHash hasher;
        switch (chunkType) {
            case 0: { // DATA
                if(clients.find(key.dst) == clients.end()) break; // for now we just keep the downloaded things from clients
                if (chunkData + 12 <= cur + chunkLen) {
                    uint32_t tsn = ntohs(*(uint32_t*)chunkData);
                    uint16_t ssn = ntohs(*(uint16_t*)chunkData + 6);
                    const uint8_t *userPtr = chunkData + 12;
                    size_t userLen = cur + chunkLen - userPtr;
                    if (userLen > 0) {
                        vector<uint8_t> vec;
                        vec.assign(userPtr, userPtr + userLen);
                        flow_data[key].streams[ssn].dataMap[tsn] = std::move(vec);
                    }
                }
                break;
            }
            case 1: { // INIT
                if(flows[key].stateMask == STATE_INIT) // if flow inited before but not answered yet, we dont touch the statistics
                    break;
                SctpFlow flowd = SctpFlow();
                flowd.first = key.src;
                flowd.second = key.dst;
                flowd.fport = key.sport; // we consider src as first and dst as second
                flowd.sport = key.dport;
                flows[key].stateMask |= STATE_INIT;
                flow_data[key] = flowd;
                tcprep.totalAssociations++;
                tcprep.openAssociations++;
                break;
            }
            case 2: { // INIT ACK
                flows[key].stateMask |= STATE_INIT_ACK;
                break;
            }
            case 10: { // COOKIE ECHO
                flows[key].stateMask |= STATE_COOKIE_ECHO;
                break;
            }
            case 11: { // COOKIE ACK => association established
                flows[key].stateMask |= STATE_STABLISHED;
                break;
            }
            case 7: { // SHUTDOWN
                // normal close
                flows[key].stateMask |= STATE_NULL;
                tcprep.normalClosed++;
                if (tcprep.openAssociations.load() > 0) tcprep.openAssociations--;
                // finalize and save data
                finalizeFlow(key);
                break;
            }
            case 6: { // ABORT
                // failed association or abort
                flows[key].stateMask |= STATE_NULL;
                if (tcprep.openAssociations.load() > 0) tcprep.openAssociations--;
                finalizeFlow(key);
                break;
            }
            default:
                break;
        }

        cur = nextChunk;
    }
}

void SctpReporter::addSctpBinary(const Binary &bin) {
    const uint8_t *data = bin.data;
    size_t len = bin.length;
    if (!data || len < 14 + 20) return; // minimal

    FlowKey key;
    const uint8_t *sctpPtr = nullptr;
    size_t sctpLen = 0;
    if (!extractSctpInfo(data, len, key, sctpPtr, sctpLen)) return;

    // update counters
    tcprep.totalSctpPackets++;
    // bytesUploaded / Downloaded estimate based on client set
    bool fromClient = clients.find(key.src) != clients.end();
    if (fromClient) tcprep.bytesUploaded += (long long)len;
    else tcprep.bytesDownloaded += (long long)len;

    handleSctpChunks(key, sctpLen, sctpPtr);
}