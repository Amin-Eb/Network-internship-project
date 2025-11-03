#pragma once
#include <stdexcept>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ndpi/ndpi_api.h>
#include <mutex>
#include "PacketBinary.h"
using namespace std;

class PacketUtils
{
public:
    PacketUtils() {
        initNdpiOnce(); 
    }
    ~PacketUtils() {
        if (g_ndpi_mod) {
            ndpi_exit_detection_module(g_ndpi_mod);
            g_ndpi_mod = nullptr;
        }
    }

    const int IPv4ETHTYPE = 0x0800, IPv6ETHTYPE = 0x86DD;
    const int IPHEADERv4 = 0x45 , IPHEADERv6 = 0x60;

    pair<const uint8_t*, size_t> getIpPacket(const Binary &bin);
    int getPacketType(const Binary &bin);

    static bool isIPv4(const uint8_t *data, size_t len);
    static bool isIPv6(const uint8_t *data, size_t len);
    static size_t flowHash(const Binary &bin);
private:
    ndpi_detection_module_struct* g_ndpi_mod = nullptr;
    once_flag ndpi_init_flag;
    void initNdpiOnce();
};