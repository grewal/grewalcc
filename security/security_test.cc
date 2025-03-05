#include "gtest/gtest.h"
#include "security.h"

namespace grewal {

TEST(SecurityTest, IsRobotsTxt_Positive) {
    Security security;
    EXPECT_TRUE(security.isRobotsTxt("robots.txt"));
    EXPECT_TRUE(security.isRobotsTxt("/robots.txt"));
}

} // namespace grewal
