#pragma once
#include <cstdint>
enum TcpStateMask : uint8_t {
    STATE_NONE       = 0,
    STATE_SYN_SENT   = 1 << 0,
    STATE_SYN_ACKED  = 1 << 1,
    STATE_ESTABLISHED= 1 << 2,
    STATE_FIN_SEEN   = 1 << 3,
    STATE_RST_SEEN   = 1 << 4,
    STATE_CLOSED     = 1 << 5
};

