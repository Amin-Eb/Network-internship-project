cmake_minimum_required(VERSION 3.10)
project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include)

option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
if(ENABLE_COVERAGE)
    message(STATUS "Coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -O0 -g")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# ---- Library ----
add_library(PacketAnalyzerLib STATIC src/PacketAnalyzer.cpp)
target_include_directories(PacketAnalyzerLib PUBLIC include)

# ---- Tests ----
enable_testing()
find_package(GTest REQUIRED)

# ---- dns ----
add_executable(dns-tests tests/test_dns.cpp)
target_include_directories(dns-tests PRIVATE include)
target_link_libraries(dns-tests
    GTest::GTest
    GTest::Main
    PacketAnalyzerLib
    Pcap++
    Packet++
    Common++
    pcap
)
add_test(NAME dns-tests COMMAND dns-tests)

# ---- http ----
add_executable(http-tests tests/test_http.cpp)
target_include_directories(http-tests PRIVATE include)
target_link_libraries(http-tests
    GTest::GTest
    GTest::Main
    PacketAnalyzerLib
    Pcap++
    Packet++
    Common++
    pcap
)
add_test(NAME http-tests COMMAND http-tests)

