#include <gtest/gtest.h>
#include "DnsAnalyzer.h"

TEST(DnsAnalyzerTest, ValidPcapFile) {
    auto stats = processPcap("../samples/capture.pcapng");
    EXPECT_EQ(stats.successful, 22);
    EXPECT_EQ(stats.unsuccessful, 1);
    EXPECT_EQ(stats.errorcode, 0);
}

TEST(DnsAnalyzerTest, NoFile) {
    auto stats = processPcap("../samples/nonexistfile.pcapng");
    EXPECT_EQ(stats.successful,  0);
    EXPECT_EQ(stats.unsuccessful,0);
    EXPECT_EQ(stats.errorcode, - 1);
}

TEST(DnsAnalyzerTest, EmptyFile){
    auto stats = processPcap("../samples/empty.pcapng");
    EXPECT_EQ(stats.successful,  0);
    EXPECT_EQ(stats.unsuccessful,0);
    EXPECT_EQ(stats.errorcode, - 2);
}