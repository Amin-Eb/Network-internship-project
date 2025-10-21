#pragma once
#include "PacketBinary.h"
#include <iostream>
#include <atomic>

using namespace std;

struct TcpReport
{
    atomic<int> openConnections{0};
    atomic<int> totalConnections{0};
    atomic<int> failedHandshakes{0};
    atomic<int> bytesUploaded{0};
    atomic<int> bytesDownloaded{0};
};

class TcpReporter
{
public:
    explicit TcpReporter(TcpReport& sharedReport)
        : tcprep(sharedReport) {}
    void addBinary(const Binary &bin);
    TcpReport& getDnsReport(){ return tcprep; }
private:
    TcpReport& tcprep;
};