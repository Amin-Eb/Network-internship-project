#pragma once
#include <string>
#include "PacketBinary.h"
#include "PacketAnalyzer.h"

class PacketCapture {
public:
    // capture from file
    static int fromFile(const std::string& filename, Reporter& analyzer);
    // capture from live interface
    static int fromInterface(const std::string& ifname,const std::string& bpf_filter, Reporter& analyzer, int limit = 0);
};
