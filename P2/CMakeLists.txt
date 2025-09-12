cmake_minimum_required(VERSION 3.10)
project(DnsAnalyzer)

set(CMAKE_CXX_STANDARD 17)

# main executable
add_executable(dns-analyzer main.cpp DnsAnalyzer.cpp)

target_include_directories(dns-analyzer PRIVATE include)
target_link_libraries(dns-analyzer
    Pcap++
    Packet++
    Common++
    pcap
)

# GoogleTest
find_package(GTest REQUIRED)

# test executable
add_executable(dns-tests test_dns.cpp DnsAnalyzer.cpp)

target_include_directories(dns-tests PRIVATE include)
target_link_libraries(dns-tests
    GTest::gtest
    GTest::gtest_main
    Pcap++
    Packet++
    Common++
    pcap
)

enable_testing()
add_test(NAME dns-tests COMMAND dns-tests)

