#pragma once
#include <cstdint>

struct Binary
{
    uint8_t *data;
    uint16_t length;
};

enum PacketType {
    DNS = 0,
    HTTP = 1,
    SIP = 2,
    NONE = 3,
};

enum TcpStateMask : uint8_t {
    STATE_NONE       = 0,
    STATE_SYN_SENT   = 1 << 0,
    STATE_SYN_ACKED  = 1 << 1,
    STATE_ESTABLISHED= 1 << 2,
    STATE_FIN_SEEN   = 1 << 3,
    STATE_RST_SEEN   = 1 << 4,
    STATE_CLOSED     = 1 << 5
};

const int ETH_HEADER_LEN = 14;
const int IPV4_HEADER_MIN_LEN = 20;
const int IPV6_HEADER_LEN = 40;
const int TCP_HEADER_MIN_LEN = 20;