#include <gtest/gtest.h>
#include "PacketCapture.h"
#include "DnsReporter.h"

using namespace std;

TEST(PacketCaptureTest, CapturePacketsFromValidFile)
{
    int recieved = 0;
    PacketCapture cap;
    Binary bin;
    EXPECT_NE(cap.openFile("samples/capture.pcapng"),0);
    while (cap.getNextPacket(bin)) {
        recieved ++;
    }
    EXPECT_EQ(recieved, 25053);
}
TEST(PacketCaptureTest, CapturePacketsFromNotValidFile)
{
    int recieved = 0;
    PacketCapture cap;
    Binary bin;
    EXPECT_EQ(cap.openFile("samples/somenotvalid.pcapng"),0);

}

#ifdef ENABLE_INTERFACE_TESTS
TEST(PacketCaptureTest, CapturePacketsFromValidInterface)
{
    int recieved = 0;
    PacketCapture cap;
    Binary bin;
    EXPECT_NE(cap.openInterface("wlp0s20f3"),0);
    while (cap.getNextPacket(bin)) {
        recieved ++;
        if(recieved == 10) break;
    }
    EXPECT_EQ(recieved, 10);
}
TEST(PacketCaptureTest, CapturePacketsFromNotValidInterface)
{
   int recieved = 0;
    PacketCapture cap;
    Binary bin;
    EXPECT_EQ(cap.openInterface("wlpnooo"),0);
}
#endif