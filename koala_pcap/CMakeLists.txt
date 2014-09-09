cmake_minimum_required(VERSION 2.8)

project(demo)

add_subdirectory(src bin)
set(CMAKE_INSTALL_PREFIX /usr/local)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
