#pragma once
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <set>
#include <tuple>
#include <string>
#include "DnsKey.h"

struct DnsStats {
    int successful = 0;
    int unsuccessful = 0;
};

// process a pcap file and return stats for dns packets
DnsStats processPcap(const std::string& filename);
