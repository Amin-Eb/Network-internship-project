#pragma once
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <iostream>
#include <tuple>
#include <string>

// DNS key: transactionID + srcIP + dstIP
using DnsKey = std::tuple<uint16_t, std::string, std::string>;

// comparator for std::set
struct DnsKeyCmp {
    bool operator()(const DnsKey& a, const DnsKey& b) const {
        if (std::get<0>(a) != std::get<0>(b)) return std::get<0>(a) < std::get<0>(b);
        if (std::get<1>(a) != std::get<1>(b)) return std::get<1>(a) < std::get<1>(b);
        return std::get<2>(a) < std::get<2>(b);
    }
};
