cmake_minimum_required(VERSION 3.10)
project(DnsAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.cpp
    DnsAnalyzer.cpp
)

# Include directories
set(PCAP /usr/local/include)
set(PCAP_LIB_DIR /usr/local/lib)

# Add executable
add_executable(dns-analyzer ${SOURCES})

# Include headers
target_include_directories(dns-analyzer PRIVATE ${PCAP})

# Link directories
link_directories(${PCAP_LIB_DIR})

# Link libraries
target_link_libraries(dns-analyzer
    Pcap++
    Packet++
    Common++
    pcap
)
