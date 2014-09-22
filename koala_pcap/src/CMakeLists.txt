include_directories(../include ../../../../cygwin/usr/include)

set(MAIN_SRC_LIST bootstrap.c yf_trim.c)

add_executable(yf_main ${MAIN_SRC_LIST})

target_link_libraries(yf_main pcap net pthread)

install(TARGETS yf_main
	LIBRARY DESTINATION /phd/bin/lib
	RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
