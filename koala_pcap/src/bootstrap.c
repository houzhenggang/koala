#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>

#include "yf_net.h"
#include "yf_trim.h"

void call(char *devStr, char *errBuf, char *exp, pcap_handler callback) {
	/* open a device, wait until a packet arrives */
	pcap_t *device = pcap_open_live(devStr, 65535, 1, 0, errBuf);

	if (!device) {
		printf("error: pcap_open_live(): %s\n", errBuf);
		exit(1);
	}

	struct bpf_program filter;
	pcap_compile(device, &filter, exp, 1, 0);
	pcap_setfilter(device, &filter);

	/* wait loop forever */
	int id = 0;
	pcap_loop(device, -1, callback, (u_char *) &id);
	pcap_close(device);
}

void loop_dev(char *errBuf, char *dev, char *exp, pcap_handler callback) {
	pcap_if_t *alldevs;

	if (pcap_findalldevs(&alldevs, errBuf) == 0) {
		int i = 0;
		for (; alldevs != NULL; alldevs = alldevs->next) {
			if (strcmp(alldevs->name, dev) == 0) {
				printf("device:%d name:%s description:%s\n", ++i, alldevs->name, alldevs->description);

				bpf_u_int32 netp; //ip
				bpf_u_int32 maskp; //subnet mask
				int ret; //return code
				ret = pcap_lookupnet(dev, &netp, &maskp, errBuf);
				if (ret == -1) {
					printf("error:%d\n", ret);
					exit(ret);
				}
				call(alldevs->name, errBuf, exp, callback);
			}
		}
	}
}

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	int *id = (int *) arg;

	printf("id: %d\n", ++(*id));
	printf("Packet length: %d\n", pkthdr->len);
	printf("Number of bytes: %d\n", pkthdr->caplen);
	printf("Received time: %s", ctime((const time_t *) &pkthdr->ts.tv_sec));

	int i;
	for (i = 0; i < pkthdr->len; ++i) {
		printf(" %02x", packet[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n\n");
}

extern void net_demo(char *src_ip_str);

int main(int argc, char **argv) {
	if (argc < 3) {
		printf("Usage:command -i [device name] [expression]\n");
		exit(-1);
	}

	char errBuf[PCAP_ERRBUF_SIZE];
	memset(errBuf, 0, sizeof(errBuf));
	char *dev = (char *) malloc(OPTION_BUF_LEN);
	memset(dev, 0, OPTION_BUF_LEN);
	char exp[1024];
	memset(exp, 0, sizeof(exp));
	printf("expression length:%d\n", sizeof(exp));
	int i;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' || argv[i][0] == '/') {
			switch (tolower(argv[i][1])) {
				case 'i':
					trim(argv[++i], dev);
					int k;
					for (k = i + 1; k < argc; k++) {
						strcat(exp, argv[k]);
						if (k < argc - 1) strcat(exp, " ");
					}
					printf("expression:%s\n", exp);
					loop_dev(errBuf, dev, exp, getPacket);
					break;
				default:
					printf("Usage:command -i [device_name]");
			}
		}
	}
	free(dev);
	return 0;
}

void net_demo(char *src_ip_str) {
	libnet_t *net_t = NULL;
	char *dev = "eth0";
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t p_tag;
	unsigned char src_mac[MAC_ADDR_LEN] = {0x00, 0x00, 0xf1, 0xe8, 0x0e, 0xc8};//发送者网卡地址

	unsigned char dst_mac[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};//接收者网卡地址

	unsigned long src_ip, dst_ip = 0;
	src_ip = libnet_name2addr4(net_t, src_ip_str, LIBNET_RESOLVE);//将字符串类型的ip转换为顺序网络字节流
	net_t = libnet_init(LIBNET_LINK_ADV, dev, err_buf);//初始化发送包结构
	if (net_t == NULL) {
		printf("libnet_init error\n");
		exit(0)

	}

	p_tag = libnet_build_arp(
			ARPHRD_ETHER,//hardware type ethernet
			ETHERTYPE_IP,//protocol type
			MAC_ADDR_LEN,//mac length
			IP_ADDR_LEN,//protocol length
			ARPOP_REPLY,//op type
			(u_int8_t *) src_mac,//source mac addr这里的作用是更新目的地的arp表
			(u_int8_t * ) & src_ip,//source ip addr
			(u_int8_t *) dst_mac,//source mac addr
			(u_int8_t * ) & dst_ip,//dest ip addr
			NULL,//payload
			0,//payload length
			net_t,//libnet context
			0//0 stands to build a new one
	);
	if (-1 == p_tag) {
		printf("libnet_build_arp error");
		exit(0);
	}

	//以太网头部
	p_tag = libnet_build_ethernet(//create ethernet header
			(u_int8_t *) dst_mac,//dest mac addr
			(u_int8_t *) src_mac,//source mac addr
			ETHERTYPE_ARP,//protocol type
			NULL,//payload
			0,//payload length
			net_t,//libnet context
			0//0 to build a new one
	);

	if (-1 == p_tag) {
		printf("libnet_build_ethernet error!\n");
		exit(1);
	}
	int res;
	if (-1 == (res = libnet_write(net_t))) {
		printf("libnet_write error!\n");
		exit(1);
	}
	libnet_destroy(net_t);
}