cmake_minimum_required(VERSION 2.8)
project(test)
set(libtest test.c)
add_library(test SHARED ${libtest})
install(FILES test.h DESTINATION /tmp/include)
install(TARGETS test 
		LIBRARY DESTINATION /tmp/lib
		ARCHIVE DESTINATION /tmp/lib)
