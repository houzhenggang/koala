set(CMAKE_INSTALL_PREFIX /usr/local)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)

include_directories(. ../include)

set(DEMO_SRC_LIST demo.c)
set(YF_TRIM_LIB_SRC_LIST yf_trim.c)
set(MAIN_SRC_LIST bootstrap.c)

add_library(yf_trim SHARED ${YF_TRIM_LIB_SRC_LIST})

add_executable(yf_demo ${DEMO_SRC_LIST})
add_executable(yf_main ${MAIN_SRC_LIST})

target_link_libraries(yf_demo pthread yf_trim)
target_link_libraries(yf_main pcap net pthread yf_trim)

install(TARGETS yf_trim yf_main yf_demo
	LIBRARY DESTINATION /phd/bin/lib
	RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
