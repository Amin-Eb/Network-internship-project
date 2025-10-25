#include "TcpReporter.h"
#include <arpa/inet.h>
#include <iostream>
#include "PacketUtils.h"
#include "PacketBinary.h"
#include "TcpNeeds.h"
#include "Constants.h"

bool TcpReporter::extractIPv4TcpInfo(const uint8_t *data, size_t len, FlowKey &key, const uint8_t* &tcpPtr, size_t &tcpLen) {
    if (len < ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN) return false;

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

void TcpReporter::handleTcpFlags(const FlowKey &key, uint8_t flags, size_t payloadLen) {
    FlowMeta &meta = flows[key];

    if (flags == 0x02) { // SYN
        if (!(meta.stateMask & STATE_SYN_SENT)) {
            meta.stateMask |= STATE_SYN_SENT;
            tcprep.totalConnections++;
            tcprep.openConnections++;
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
    if (flags == 0x011) { // FIN + ACK
        meta.stateMask |= STATE_FIN_SEEN;
        if (meta.stateMask & STATE_ESTABLISHED) {
            tcprep.normalClosed++;
            tcprep.openConnections--;
        }
    }
    if (flags == 0x04) { // RST
        meta.stateMask |= STATE_RST_SEEN;
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

    bool ok = false;
    if (PacketUtils::isIPv4(data, len)) ok = extractIPv4TcpInfo(data, len, key, tcpPtr, tcpLen);
    else if (PacketUtils::isIPv6(data, len)) ok = extractIPv6TcpInfo(data, len, key, tcpPtr, tcpLen);
    if (!ok) return;
    tcprep.totalTcpPackets++;
    if (key.src == client)
            tcprep.bytesUploaded += bin.length;
        else
            tcprep.bytesDownloaded += bin.length;
    uint8_t dataOffset = (tcpPtr[12] >> 4) * 4;
    uint8_t flags = tcpPtr[13];
    size_t payloadLen = tcpLen > dataOffset ? tcpLen - dataOffset : 0;

    handleTcpFlags(key, flags, payloadLen);
}
