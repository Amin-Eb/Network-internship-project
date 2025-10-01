#include <gtest/gtest.h>
#include "PacketCapture.h"
#include "DnsReporter.h"

using namespace std;

TEST(PacketCaptureTest, CapturePacketsFromValidFile)
{
    Reporter rep;
    EXPECT_EQ(PacketCapture::fromFile("samples/capture.pcapng", rep), 0);
    EXPECT_EQ(rep.getReport().recieved, 25053);
}
TEST(PacketCaptureTest, CapturePacketsFromNotValidFile)
{
    Reporter rep;
    EXPECT_EQ(PacketCapture::fromFile("samples/randomadress.pcapng", rep), -1);
}
/*      this tests commented because interface of diffrent devices specially github actions env might be differ
                                        this function should be used under root user
                                        but results of local run mentioned in README
TEST(PacketCaptureTest, CapturePacketsFromValidInterface)
{
    Reporter rep;
    EXPECT_EQ(PacketCapture::fromInterface("wlp0s20f3", "", rep, 10), 0);    
    EXPECT_EQ(rep.getReport().recieved, 10);
}
TEST(PacketCaptureTest, CapturePacketsFromNotValidInterface)
{
    Reporter rep;
    EXPECT_EQ(-1,PacketCapture::fromInterface("wlp0s20f", "", rep, 10));    
}
*/