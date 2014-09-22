#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <libnet.h>
#include <pcap.h>

#include "yf_net.h"
#include "yf_trim.h"

extern void proc_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
extern void call(char *errBuf, char *devStr, char *exp, pcap_handler callback);
extern void* pthread_run(void*);
extern void send_msg(struct sniff_ethernet *eth, struct sniff_ip *ip, struct sniff_tcp *tcp, int dlen, char *data, char *payload);
extern int check(char *errbuf, char *dev);

int main(int argc, char **argv) {
	pthread_t pid_a; //

	pdt_args_t p_a;
	memset(p_a.errbuf, 0, sizeof(p_a.errbuf));
	memset(p_a.dev, 0, sizeof(p_a.dev));
	memset(p_a.exp, 0, sizeof(p_a.exp));

	int ch;
	int k = 0;
	opterr = 0;
	while ((ch = getopt(argc, argv, "i:d:")) != EOF) {
		switch (ch) {
			case 'i':
				trim(optarg, p_a.dev);
				break;
			case 'd':
				p_a.dst = optarg;
				break;
			default:
				k = argc - 1;
		}
	}

	if (k >= optind) {
		printf("Usage:command -i [device name] [expression]\n");
		exit(-1);
	}

	for (k = optind; k < argc; k++) {
		strcat(p_a.exp, argv[k]);
		if (k < argc - 1)
			strcat(p_a.exp, " ");
	}
	int a_status = pthread_create(&pid_a, NULL, pthread_run, &p_a);
	if (a_status != 0) {
		printf("ERROR.");
		exit(-1);
	}
	pthread_join(pid_a, NULL);

	return 0;
}

void call(char *errBuf, char *devStr, char *exp, pcap_handler callback) {
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

int check(char *errbuf, char *dev) {
	pcap_if_t *alldevs;

	if (pcap_findalldevs(&alldevs, errbuf) == 0) {
		printf("devices:[ ");
		for (; alldevs != NULL; alldevs = alldevs->next) {
			printf("%s ", alldevs->name);
			if (strcmp(alldevs->name, dev) == 0) {
				return 0;
			}
		}
		puts("]");
	}
	return -1;
}

void* pthread_run(void *arg) {
	pdt_args_t p_a = *(pdt_args_t *) arg;
	printf("dev:%s exp:%s\n", p_a.dev, p_a.exp);

	if (check(p_a.errbuf, p_a.dev) != 0) {
		printf("Not found device:%s\n", p_a.dev);
		exit(-1);
	} else {
		bpf_u_int32 netp; //ip
		bpf_u_int32 maskp; //subnet mask
		int ret; //return code
		ret = pcap_lookupnet(p_a.dev, &netp, &maskp, p_a.errbuf);
		if (ret == -1) {
			printf("error:%d\n", ret);
			exit(ret);
		}
		call(p_a.errbuf, p_a.dev, p_a.exp, proc_packet);
	}
}

void proc_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	int *id = (int *) arg;

	printf("id: %d\n", ++(*id));
	printf("Packet length: %d\n", pkthdr->len);
	printf("Number of bytes: %d\n", pkthdr->caplen);
	printf("Received time: %s", ctime((const time_t *) &pkthdr->ts.tv_sec));

	/*
	 int i;
	 for (i = 0; i < pkthdr->len; ++i) {
	 printf(" %02x", packet[i]);
	 if ((i + 1) % 16 == 0) {
	 printf("\n");
	 }
	 }
	 printf("\n\n");
	 */

	struct sniff_ethernet *ethernet; //以太网包头
	struct sniff_ip *ip; //ip包头
	struct sniff_tcp *tcp; //tcp包头
	char *data; //http packet

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*) (packet);
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	data = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
	int dlen = ntohs(ip->ip_len) - size_ip - size_tcp;

	printf("ethernet_h length:%d\n", SIZE_ETHERNET);
	printf("ip_h length:%d\n", size_ip);
	printf("ip_total length:%d\n", ip->ip_len);
	printf("tcp_h length:%d\n", size_tcp);
	printf("src:%s:%d  dst:%s:%d data_len:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport), dlen);

	if (dlen > 0) {
		//send packet
		char payload[4] = { 0x01, 0x02, 0x03, 0x04 };
		send_msg(ethernet, ip, tcp, dlen, data, payload);
	}
}

void send_msg(struct sniff_ethernet *eth, struct sniff_ip *ip, struct sniff_tcp *tcp, int dlen, char *data, char *payload) {
	u_int32_t payload_s = strlen(payload);
	libnet_t *net_t = NULL;
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t p_tag;

	u_char src_mac[ETHER_ADDR_LEN]; //发送者网卡地址
	u_char dst_mac[ETHER_ADDR_LEN]; //接收者网卡地址

	strcpy(src_mac, eth->ether_dhost);
	strcpy(dst_mac, eth->ether_shost);
	printf("src_mac:");
	p0x_u_char(6, src_mac);
	printf("dst_mac:");
	p0x_u_char(6, dst_mac);
	printf("\n\n");

	u_int32_t src_ip, dst_ip = 0;
	u_char src_ip_addr[16];
	u_char dst_ip_addr[16];
	strcpy(src_ip_addr, inet_ntoa(ip->ip_dst));
	strcpy(dst_ip_addr, inet_ntoa(ip->ip_src));

	src_ip = libnet_name2addr4(net_t, src_ip_addr, LIBNET_RESOLVE); //将字符串类型的ip转换为顺序网络字节流
	dst_ip = libnet_name2addr4(net_t, dst_ip_addr, LIBNET_RESOLVE);
	u_int32_t src_port, dst_port;
	src_port = ntohs(tcp->th_dport);
	dst_port = ntohs(tcp->th_sport);

	printf("send from:%s:%d to:%s:%d\n", src_ip_addr, src_port, dst_ip_addr, dst_port);
	net_t = libnet_init(LIBNET_LINK_ADV, NULL, err_buf); //初始化发送包结构
	if (net_t == NULL) {
		printf("libnet_init error\n");
		return;
	}
	//TCP
	p_tag = libnet_build_tcp(
			src_port,
			dst_port,
			0x01010101,
			0x02020202,
			TH_SYN,
			32767,
			0,
			10,
			LIBNET_TCP_H + 20 + payload_s,
			(uint8_t*) payload,
			payload_s,
			net_t,
			0);
	if (p_tag == -1) {
		printf("libnet_build_tcp error");
		return;
	}
	//IP
	u_int16_t len = LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_s;
	p_tag = libnet_build_ipv4(
			len, /* length */
			0, /* TOS */
			0x42, /* IP ID */
			0, /* IP Frag */
			64, /* TTL */
			IPPROTO_TCP, /* protocol */
			0, /* checksum */
			src_ip, /* source IP */
			dst_ip, /* destination IP */
			NULL, /* payload */
			0, /* payload size */
			net_t, /* libnet handle */
			0);
	if (p_tag == -1) {
		printf("libnet_build_ipv4 error");
		return;
	}
	//Ethernet
	p_tag = libnet_build_ethernet(
			(u_int8_t *) dst_mac, //dest mac addr
			(u_int8_t *) src_mac, //source mac addr
			ETHERTYPE_ARP, //protocol type
			NULL, //payload
			0, //payload length
			net_t, //libnet context
			0 //0 to build a new one
			);
	if (p_tag == -1) {
		printf("libnet_build_ethernet error!\n");
	}
	else {
		int packet_size;
		packet_size = libnet_write(net_t);
		if (packet_size == -1) {
			printf("libnet_write error!\n");
		}
	}
	libnet_destroy(net_t);
}
