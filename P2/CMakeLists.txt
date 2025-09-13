cmake_minimum_required(VERSION 3.10)
project(DnsAnalyzer)

set(CMAKE_CXX_STANDARD 17)

# Tell CMake where our headers live
include_directories(${PROJECT_SOURCE_DIR}/include)

# DNS analyzer executable
add_executable(dns-analyzer
    src/main.cpp
    src/DnsAnalyzer.cpp
)

target_link_directories(dns-analyzer PRIVATE /usr/local/lib)

target_link_libraries(dns-analyzer
    Pcap++
    Packet++
    Common++
    pcap
)

# ---- Tests ----
enable_testing()
find_package(GTest REQUIRED)

add_executable(dns-tests
    tests/test_dns.cpp
    src/DnsAnalyzer.cpp   # link implementation for tests
)

target_include_directories(dns-tests PRIVATE include)
target_link_libraries(dns-tests
    GTest::GTest
    GTest::Main
    Pcap++
    Packet++
    Common++
    pcap
)

add_test(NAME dns-tests COMMAND dns-tests)
