include_directories(../include)

set(SRC_LIST test.c)
set(DEMO_SRC_LIST demo.c)
set(YF_TRIM_LIB_SRC_LIST yf_trim.c)

add_library(yf_trim SHARED ${YF_TRIM_LIB_SRC_LIST})

add_executable(test ${SRC_LIST})
add_executable(demo ${DEMO_SRC_LIST})

target_link_libraries(test pcap yf_trim)
target_link_libraries(demo pthread yf_trim)

install(TARGETS yf_trim test
	LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
	RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
