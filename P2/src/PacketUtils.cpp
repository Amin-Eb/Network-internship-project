#include "PacketUtils.h"
#include "Constants.h"


void PacketUtils::initNdpiOnce(){
    call_once(ndpi_init_flag, [this](){
        g_ndpi_mod = ndpi_init_detection_module(NULL);
        if (!g_ndpi_mod) 
        {
            cerr << "ndpi falied!" << endl;
            return;
        }
        ndpi_load_protocols_file(g_ndpi_mod, NULL);  // load default protocols
        ndpi_finalize_initialization(g_ndpi_mod);
    });
}

pair<const uint8_t*, size_t> PacketUtils::getIpPacket(const Binary &bin) {
    const uint8_t* data = bin.data;
    size_t len = bin.length;

    // ---  Ethernet/IP detection ---
    uint16_t ethType = (data[12] << 8) | data[13];
    size_t ipOffset = 0;
    if (ethType == IPv4ETHTYPE || ethType == IPv6ETHTYPE) { // IPv4 or IPv6
        ipOffset = 14; // skip Ethernet header because ndpi doesnt work with it and no result
        ethType = ntohs(ethType);
    } else if (data[0] == IPHEADERv4 || data[0] == IPHEADERv6) {
        ipOffset = 0;
    } else {
        return {data, -1}; // unknown type   or errors , we use -1 in second of pair as error
    }

    if (len <= ipOffset)
        return {data, -1};
    
    const uint8_t* ipPacket = data + ipOffset; // move pointer after eth part
    size_t ipLen = len - ipOffset;
    return {ipPacket , ipLen};
}

int PacketUtils::getPacketType(const Binary &bin) {
    if (!bin.data || bin.length < 1)
        return NONE;

    if (!g_ndpi_mod)
        return NONE;

    auto fetchedIpPacket = getIpPacket(bin);

    if (fetchedIpPacket.second == -1) 
        return NONE;

    const uint8_t* ipPacket = fetchedIpPacket.first; 
    size_t ipLen = fetchedIpPacket.second;

    struct ndpi_flow_struct flow{};
    memset(&flow, 0, sizeof(flow));

    struct ndpi_proto proto = ndpi_detection_process_packet(
        g_ndpi_mod,
        &flow,
        (uint8_t*)ipPacket,
        ipLen,
        0,
        nullptr
    );

    uint16_t detected = (proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
                            ? proto.proto.app_protocol
                            : proto.proto.master_protocol;
    switch (detected) {
        case NDPI_PROTOCOL_MDNS:
            return DNS;
        case NDPI_PROTOCOL_DNS: 
            return DNS;
        case NDPI_PROTOCOL_HTTP:
            return HTTP;
        case NDPI_PROTOCOL_HTTP_CONNECT:
            return HTTP;
        case NDPI_PROTOCOL_HTTP_PROXY:
            return HTTP;
        case NDPI_PROTOCOL_SIP: 
            return SIP;  
        default: return NONE;
    }
}

bool PacketUtils::isIPv4(const uint8_t *data, size_t len) 
{ 
    if (len < ETH_HEADER_LEN + 1) return false;
    uint8_t version = (data[ETH_HEADER_LEN] >> 4) & 0xF;
    return version == 4;
}

bool PacketUtils::isIPv6(const uint8_t *data, size_t len) 
{
    if (len < ETH_HEADER_LEN + 1) return false;
    uint8_t version = (data[ETH_HEADER_LEN] >> 4) & 0xF;
    return version == 6;
}

size_t PacketUtils::flowHash(const Binary &bin)
{
    bool ip4 = isIPv4(bin.data, bin.length);
    bool ip6 = isIPv6(bin.data, bin.length);

    uint64_t srcAddr;
    uint64_t dstAddr;
    uint16_t srcPort;
    uint16_t dstPort; 

    if(ip4){
        srcAddr = ((bin.data[26] << 24) | (bin.data[27] << 16) | (bin.data[28] << 8) | (bin.data[29]));
        dstAddr = ((bin.data[30] << 24) | (bin.data[31] << 16) | (bin.data[32] << 8) | (bin.data[33]));
        srcPort = ntohs((bin.data[34] << 8) | (bin.data[35])); // no matter udp or tcp, first two bytes after ip part is about source port!
        dstPort = ntohs((bin.data[36] << 8) | (bin.data[37]));
    }
    else{
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, bin.data + 14 + 40 + 8, src, sizeof(src));
        inet_ntop(AF_INET6, bin.data + 14 + 40 + 24, dst, sizeof(dst));
        srcAddr = std::hash<string>{}(src);
        dstAddr = std::hash<string>{}(dst);
        srcPort = ntohs((bin.data[54] << 8) | (bin.data[55])); // no matter udp or tcp, first two bytes after ip part is about source port!
        dstPort = ntohs((bin.data[56] << 8) | (bin.data[57]));
    }
    size_t seed = 0;
    seed ^= std::hash<uint64_t>{}(srcAddr + dstAddr + srcPort + dstPort);
    return seed;
}