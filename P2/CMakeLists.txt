cmake_minimum_required(VERSION 3.10)
project(DnsAnalyzer)

set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
if(ENABLE_COVERAGE)
    message(STATUS "Coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -O0 -g")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# ---- Library ----
add_library(DnsAnalyzerLib STATIC src/DnsAnalyzer.cpp)
target_include_directories(DnsAnalyzerLib PUBLIC include)

# ---- Tests ----
enable_testing()
find_package(GTest REQUIRED)

add_executable(dns-tests tests/test_dns.cpp)
target_include_directories(dns-tests PRIVATE include)
target_link_libraries(dns-tests
    GTest::GTest
    GTest::Main
    DnsAnalyzerLib
    Pcap++
    Packet++
    Common++
    pcap
)

add_test(NAME dns-tests COMMAND dns-tests)
