cmake_minimum_required(VERSION 3.19)
project(beacon_flood)

set(CMAKE_CXX_STANDARD 14)
include(FindPCAP.cmake)

add_executable(beacon_flood main.cpp)
target_link_libraries(beacon_flood ${PCAP_LIBRARY})