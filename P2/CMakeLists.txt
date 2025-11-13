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
find_package(prometheus-cpp REQUIRED)

set(NDPI_INCLUDE_DIR "/usr/local/include/ndpi")
set(NDPI_LIBRARY "/usr/local/lib/libndpi.so")

if (EXISTS "${NDPI_INCLUDE_DIR}/ndpi_api.h" AND EXISTS "${NDPI_LIBRARY}")
    include_directories(${NDPI_INCLUDE_DIR})
    link_libraries(${NDPI_LIBRARY})
else()
    message(FATAL_ERROR "nDPI not found at ${NDPI_INCLUDE_DIR}")
endif()

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
    src/TcpReporter.cpp
)
target_include_directories(PacketAnalyzerLib PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
    ${NDPI_INCLUDE_DIR}
)


# ---- Capture library ----
add_library(PacketCaptureLib STATIC
    src/PacketCapture.cpp
)

target_include_directories(PacketCaptureLib PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${libpcap_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/3rdparty
)

target_link_libraries(PacketCaptureLib
    PacketAnalyzerLib       # user of analyzer
    libpcap::libpcap        # direct libpcap dependency
)

# ---- Utils library ----
add_library(PacketUtilsLib STATIC 
    src/PacketUtils.cpp
)
target_include_directories(PacketUtilsLib PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
    ${NDPI_INCLUDE_DIR}
)

# ---- statistics ----
add_executable(statistics src/statistics.cpp)

target_include_directories(statistics PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
)

target_link_libraries(statistics
    prometheus-cpp::prometheus-cpp
    PacketAnalyzerLib
    PacketCaptureLib
    PacketUtilsLib
    httplib::httplib 
    PcapPlusPlus::PcapPlusPlus
)

# ---- Tests ----
enable_testing()



# ---- dns ----
add_executable(dns-tests tests/test_dns.cpp)
target_include_directories(dns-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
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
    ${PROJECT_SOURCE_DIR}/3rdparty
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
    ${PROJECT_SOURCE_DIR}/3rdparty
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

# ---- utils ----
add_executable(utils-tests tests/test_utils.cpp)
target_include_directories(utils-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(utils-tests
    PacketUtilsLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
)
add_test(NAME utils-tests COMMAND utils-tests)

# ---- analyzer ----
add_executable(analyzer-tests tests/test_analyzer.cpp)
target_include_directories(analyzer-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(analyzer-tests
    PacketAnalyzerLib
    PacketUtilsLib
    PacketCaptureLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
)
add_test(NAME analyzer-tests COMMAND analyzer-tests)

# ---- tcp ----
add_executable(tcp-tests tests/test_tcp.cpp)
target_include_directories(tcp-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(tcp-tests
    PacketAnalyzerLib
    PacketUtilsLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    pcapplusplus::packet
    pcapplusplus::common
    libpcap::libpcap
)
add_test(NAME tcp-tests COMMAND tcp-tests)

# ---- tcp ----
add_executable(sctp-tests tests/test_sctp.cpp)
target_include_directories(sctp-tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)
target_link_libraries(sctp-tests
    PacketAnalyzerLib
    PacketUtilsLib
    GTest::gtest
    GTest::gtest_main
    pcapplusplus::pcap
    pcapplusplus::packet
    pcapplusplus::common
    libpcap::libpcap
)
add_test(NAME sctp-tests COMMAND sctp-tests)

