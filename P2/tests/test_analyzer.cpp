#include <gtest/gtest.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include "PacketUtils.h"
#include "PacketAnalyzer.h"
#include "PacketCapture.h"
#include <cstring>

using namespace std;

// ----------------- shared Reports -----------------
DnsReport dnsrep;
HttpReport httprep;
SipReport siprep;

Report sharedrep;

TEST(AnalyzerTest, addBinarytest)
{
    sharedrep.dnsreport = &dnsrep;
    sharedrep.httpreport = &httprep;
    sharedrep.sipreport = &siprep;
    Reporter reporter(sharedrep);

    PacketCapture cap;
    Binary bin;

    if (!cap.openFile("capture.pcapng")) {
        cerr << "Failed to open interface or file!" << endl;
    }
    
    while (cap.getNextPacket(bin))
        reporter.addBinary(bin);


    EXPECT_EQ(reporter.getReport().recieved.load(), 25053);
    //protocols data verification done in theirseves tests.
}