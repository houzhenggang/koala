set(SRC_LIST test.c)
set(DEMO_SRC_LIST demo.c)
set(YF_TRIM_LIB_SRC_LIST yf_trim.c)
set(MAIN_SRC_LIST main.cpp)

add_library(yf_trim SHARED ${YF_TRIM_LIB_SRC_LIST})

add_executable(phd_test ${SRC_LIST})
add_executable(phd_demo ${DEMO_SRC_LIST})
add_executable(phd_main ${MAIN_SRC_LIST})

target_link_libraries(phd_test pcap yf_trim)
target_link_libraries(phd_demo pthread yf_trim)
target_link_libraries(phd_main pcap pthread yf_trim)

install(TARGETS yf_trim phd_test phd_main phd_demo
	LIBRARY DESTINATION /phd/bin/lib
	RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
