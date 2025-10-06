cmake_minimum_required(VERSION 3.10)
project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 17)

# Conan integration
include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)

# Find Conan packages
find_package(GTest REQUIRED)
find_package(PcapPlusPlus REQUIRED)
find_package(libpcap REQUIRED)
find_package(httplib REQUIRED)

# Debug output to verify PcapPlusPlus and libpcap
message(STATUS "PcapPlusPlus_FOUND: ${PcapPlusPlus_FOUND}")
message(STATUS "PcapPlusPlus_INCLUDE_DIRS: ${PcapPlusPlus_INCLUDE_DIRS}")
message(STATUS "PcapPlusPlus_LIBRARIES: ${PcapPlusPlus_LIBRARIES}")
message(STATUS "libpcap_FOUND: ${libpcap_FOUND}")
message(STATUS "libpcap_INCLUDE_DIRS: ${libpcap_INCLUDE_DIRS}")
message(STATUS "libpcap_LIBRARIES: ${libpcap_LIBRARIES}")

# Copy sample files to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/samples DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Coverage option
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
if(ENABLE_COVERAGE)
    message(STATUS "Coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -O0 -g")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# ---- Analyzer Library ----
add_library(PacketAnalyzerLib STATIC 
    src/PacketAnalyzer.cpp 
    src/DnsReporter.cpp 
    src/HttpReporter.cpp 
    src/SipReporter.cpp
)
target_include_directories(PacketAnalyzerLib PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)


# ---- Capture library ----
add_library(PacketCaptureLib STATIC
    src/PacketCapture.cpp
)

target_include_directories(PacketCaptureLib PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${libpcap_INCLUDE_DIRS}
)

target_link_libraries(PacketCaptureLib
    PacketAnalyzerLib       # user of analyzer
    libpcap::libpcap        # direct libpcap dependency
)

# ---- Tests ----
enable_testing()

# ---- dns ----
add_executable(dns-tests tests/test_dns.cpp)
target_include_directories(dns-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(dns-tests
    PacketAnalyzerLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    pcapplusplus::packet
    pcapplusplus::common
    libpcap::libpcap
)
add_test(NAME dns-tests COMMAND dns-tests)

# ---- http ----
add_executable(http-tests tests/test_http.cpp)
target_include_directories(http-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(http-tests
    PacketAnalyzerLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    pcapplusplus::packet
    pcapplusplus::common
    libpcap::libpcap
)
add_test(NAME http-tests COMMAND http-tests)

# ---- sip ----
add_executable(sip-tests tests/test_sip.cpp)
target_include_directories(sip-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(sip-tests
    PacketAnalyzerLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    pcapplusplus::packet
    pcapplusplus::common
    libpcap::libpcap
)
add_test(NAME sip-tests COMMAND sip-tests)

# ---- capture ----
add_executable(capture-tests tests/test_capture.cpp)
target_link_libraries(capture-tests
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    pcapplusplus::packet
    pcapplusplus::common
    PacketCaptureLib
    PacketAnalyzerLib
    libpcap::libpcap
)
option(ENABLE_INTERFACE_TESTS "Enable tests that require a real network interface" OFF)
if(ENABLE_INTERFACE_TESTS)
    add_compile_definitions(ENABLE_INTERFACE_TESTS)
endif()
add_test(NAME capture-tests COMMAND capture-tests)

# ---- analyzer ----
add_executable(analyzer-tests tests/test_analyzer.cpp)
target_include_directories(analyzer-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(analyzer-tests
    PacketAnalyzerLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    PacketAnalyzerLib
)
add_test(NAME analyzer-tests COMMAND analyzer-tests)


# ---- statistics ----
add_executable(statistics
    src/statistics.cpp
)

target_include_directories(statistics PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(statistics
    PacketAnalyzerLib
    PacketCaptureLib
    httplib::httplib 
    PcapPlusPlus::PcapPlusPlus
)