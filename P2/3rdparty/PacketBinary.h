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