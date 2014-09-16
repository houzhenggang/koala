cmake_minimum_required(VERSION 2.8.11)
project(koala_pcap)

add_subdirectory(src)
set(CMAKE_INSTALL_PREFIX /usr/local)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
