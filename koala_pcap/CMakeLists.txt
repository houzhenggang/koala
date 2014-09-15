cmake_minimum_required(VERSION 2.8.4)
project(koala_pcap)
include_directories(include)
add_subdirectory(src bin)
set(CMAKE_INSTALL_PREFIX /usr/local)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)

#set(SOURCE_FILES main.cpp)
#add_executable(koala_pcap ${SOURCE_FILES})