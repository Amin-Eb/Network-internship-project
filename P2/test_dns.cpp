#include <gtest/gtest.h>
#include "DnsAnalyzer.h"

TEST(DnsAnalyzerTest, CanParsePcap) {
    auto stats = processPcap("../capture.pcapng");
    EXPECT_GE(stats.successful, 0);
    EXPECT_GE(stats.unsuccessful, 0);
}

TEST(DnsAnalyzerTest, EmptyFile) {
    auto stats = processPcap("../empty.pcapng");
    EXPECT_EQ(stats.successful, 0);
    EXPECT_EQ(stats.unsuccessful, 0);
}

