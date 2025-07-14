cmake_minimum_required(VERSION 3.16)
project(send-arp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# PCH 설정
set(CMAKE_PCH_ENABLED ON)
set(CMAKE_PCH_FILE "src/pch.h")

add_executable(send-arp
    src/main.cpp
    src/pch.cpp
    src/pch.h
    src/arphdr.cpp
    src/arphdr.h
    src/ethhdr.cpp
    src/ethhdr.h
    src/ip.cpp
    src/ip.h
    src/mac.cpp
    src/mac.h
)

target_precompile_headers(send-arp PRIVATE src/pch.h)

include(GNUInstallDirs)
install(TARGETS send-arp
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_include_directories(send-arp PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(send-arp PRIVATE ${PCAP_LIBRARIES})
