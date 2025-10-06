#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <httplib.h>

#include "PacketCapture.h"
#include "PacketAnalyzer.h"

using namespace std;
using namespace httplib;

DnsReport dnsrep;
HttpReport httprep;
SipReport siprep;

Report sharedrep;

int main(){
    sharedrep.dnsreport = &dnsrep;
    sharedrep.httpreport = &httprep;
    sharedrep.sipreport = &siprep;

    Reporter reporter(sharedrep); // wraps the analyzers

    PacketCapture cap;
    Binary bin;
    int recieved = 0;
    cap.openFile("samples/capture.pcapng");
    while (cap.getNextPacket(bin)) {
        reporter.addBinary(bin);
    }
    cout << recieved << endl;
    cout << reporter.getReport().dnsreport->totalDns.load() << endl;
}