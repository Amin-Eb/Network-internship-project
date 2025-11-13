#pragma once
#include <cstdint>
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr int SCTP_NUMBER = 132;

enum TcpStateMask : uint8_t {
    STATE_NULL       = 0 << 0,
    STATE_INIT       = 1 << 0,
    STATE_INIT_ACK   = 1 << 1,
    STATE_COOKIE_ECHO= 1 << 2,
    STATE_STABLISHED = 1 << 3,
};

