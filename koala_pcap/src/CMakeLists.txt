include_directories(../include /usr/include /usr/local/include)

set(TEST_SRC_LIST pcap/test.c)
set(DEMO_SRC_LIST demo.c)
set(TCP_SERVER_SRC tcp/tcp_server.c)
set(TCP_CLIENT_SRC tcp/tcp_client.c)
set(PHD_TRIM_LIB_SRC_LIST lib/phd_trim.c)

set(UDP_SENDER_SRC udp/udp_sender.c)
set(UDP_RECEIVE_SRC udp/udp_receive.c)

add_library(phd_trim SHARED ${PHD_TRIM_LIB_SRC_LIST})

add_executable(test ${TEST_SRC_LIST})
add_executable(test1 pcap/test1.c)
add_executable(demo ${DEMO_SRC_LIST})
add_executable(tcp_server ${TCP_SERVER_SRC})
add_executable(tcp_client ${TCP_CLIENT_SRC})

add_executable(udp_sender ${UDP_SENDER_SRC})
add_executable(udp_receive ${UDP_RECEIVE_SRC})

link_directories(/usr/lib64/)

target_link_libraries(test pcap phd_trim)
target_link_libraries(test1 pcap phd_trim)
target_link_libraries(demo phd_trim)

install(TARGETS phd_trim test demo tcp_server tcp_client
	LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
	RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
