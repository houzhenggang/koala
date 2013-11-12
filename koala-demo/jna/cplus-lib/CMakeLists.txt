cmake_minimum_required(VERSION 2.8)
project(demo)
set(libdemo demo.cpp)
add_library(demo SHARED ${libdemo})
install(FILES demo.h DESTINATION /tmp/include)
install(TARGETS demo 
		LIBRARY DESTINATION /tmp/lib
		ARCHIVE DESTINATION /tmp/lib)
