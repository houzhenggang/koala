#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <libnet.h>
#include <pcap.h>
#include <sys/timeb.h>

#include "yf_net.h"
#include "yf_trim.h"

extern void proc_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
extern void call(pcap_handler callback);
extern void* pthread_run(void*);
extern int send_packet(u_int32_t src_ip, u_int16_t src_port, u_int32_t dst_ip, u_int16_t dst_port, u_int32_t seq, u_int32_t ack, u_int32_t payload_s, char *payload);
extern int check(char *errbuf, char *dev);
//
static pdt_args_t pat;
static libnet_t *net_t = NULL;
static libnet_ptag_t p_tag;
static char payload[4] = { 0x01, 0x02, 0x03, 0x04 };
int main(int argc, char **argv) {
	pthread_t pid_a; //

	memset(pat.errbuf, 0, sizeof(pat.errbuf));
	memset(pat.in_dev, 0, sizeof(pat.in_dev));
	memset(pat.exp, 0, sizeof(pat.exp));

	int ch;
	int k = 0;
	opterr = 0;
	while ((ch = getopt(argc, argv, "i:o:")) != EOF) {
		switch (ch) {
			case 'i':
				trim(optarg, pat.in_dev);
				break;
			case 'o':
				trim(optarg, pat.out_dev);
				break;
			default:
				break;
		}
	}
	if (strlen(pat.in_dev) < 1) {
		printf("Usage:command -i [listen device name] -o [send packet device name] [expression]\n");
		exit(-1);
	}
	//初始化发送包结构
	net_t = libnet_init(LIBNET_RAW4, pat.out_dev, pat.errbuf);
	if (net_t == NULL) {
		printf("libnet_init error\n");
		return -1;
	}

	for (k = optind; k < argc; k++) {
		strcat(pat.exp, argv[k]);
		if (k < argc - 1)
			strcat(pat.exp, " ");
	}
	int a_status = pthread_create(&pid_a, NULL, pthread_run, &pat);
	if (a_status != 0) {
		printf("ERROR.");
		exit(-1);
	}
	pthread_join(pid_a, NULL);

	return 0;
}

void call(pcap_handler callback) {
	/* open a device, wait until a packet arrives */
	pcap_t *device = pcap_open_live(pat.in_dev, 65535, 1, 0, pat.errbuf);

	if (!device) {
		printf("error: pcap_open_live(): %s\n", pat.errbuf);
		exit(1);
	}

	struct bpf_program filter;
	pcap_compile(device, &filter, pat.exp, 1, 0);
	pcap_setfilter(device, &filter);

	/* wait loop forever */
	int id = 0;
	pcap_loop(device, -1, callback, (u_char *) &id);
	pcap_close(device);
}

int check(char *errbuf, char *dev) {
	pcap_if_t *alldevs;
	int flag = -1;
	if (pcap_findalldevs(&alldevs, errbuf) == 0) {
		printf("devices:[ ");
		for (; alldevs != NULL; alldevs = alldevs->next) {
			printf("%s ", alldevs->name);
			if (strcmp(alldevs->name, dev) == 0) {
				flag = 0;
			}
		}
		printf("]\n");
	}
	return flag;
}

void* pthread_run(void *arg) {
	pdt_args_t pat = *(pdt_args_t *) arg;
	printf("dev:%s exp:%s\n", pat.in_dev, pat.exp);

	if (check(pat.errbuf, pat.in_dev) != 0) {
		printf("Not found device:%s\n", pat.in_dev);
		exit(-1);
	}
	bpf_u_int32 netp; //ip
	bpf_u_int32 maskp; //subnet mask
	int ret; //return code
	ret = pcap_lookupnet(pat.in_dev, &netp, &maskp, pat.errbuf);
	if (ret == -1) {
		printf("error:%d\n", ret);
		exit(-1);
	}
	call(proc_packet);
}

void proc_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	//time
	struct timeb timebuffer1, timebuffer2;
	time_t time1, time2;
	unsigned short millitm1, millitm2;
	//time

	int *id = (int *) arg;

	struct sniff_ethernet *ethhdr; //以太网包头
	struct sniff_ip *iphdr; //ip包头
	struct sniff_tcp *tcphdr; //tcp包头
	char *data; //http packet

	u_int size_tcp, size_ip, dlen = 0;

	ethhdr = (struct sniff_ethernet*) (packet);

	switch (ntohs(ethhdr->ether_type)) {
		case ETHERTYPE_ARP:
			printf("ARP\n");
			break;
		case ETHERTYPE_IP:
			iphdr = (struct sniff_ip*) (packet + SIZE_ETHERNET);
			switch (iphdr->ip_p) {
				case IPPROTO_TCP:
					size_ip = IP_HL(iphdr) * 4;
					tcphdr = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
					size_tcp = TH_OFF(tcphdr) * 4;
					data = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
					dlen = ntohs(iphdr->ip_len) - size_ip - size_tcp;

					u_int32_t src_port, dst_port;
					src_port = ntohs(tcphdr->th_dport);
					dst_port = ntohs(tcphdr->th_sport);

					if ((tcphdr->th_flags & (TH_ACK | TH_SYN) == (TH_ACK | TH_SYN)) && (tcphdr->th_flags & TH_RST) != TH_RST) {
						send_packet(iphdr->ip_dst.s_addr, src_port, iphdr->ip_src.s_addr, dst_port, ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack), 4, payload);
						send_packet(iphdr->ip_src.s_addr, dst_port, iphdr->ip_dst.s_addr, src_port, ntohl(tcphdr->th_ack), ntohl(tcphdr->th_seq), 4, payload);
						u_char src_ip_addr[16], dst_ip_addr[16];
						strcpy(src_ip_addr, inet_ntoa(iphdr->ip_src));
						strcpy(dst_ip_addr, inet_ntoa(iphdr->ip_dst));
						printf("RST: %s<->%s\n", src_ip_addr, dst_ip_addr);
					}
					/*
					 printf("ethernet_h length:%d\n", SIZE_ETHERNET);
					 printf("ip_h length:%d\n", size_ip);
					 printf("ip_total length:%d\n", ntohs(iphdr->ip_len));
					 printf("tcp_h length:%d\n", size_tcp);
					 printf("src:%s:%d  dst:%s:%d data_len:%d\n", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport), inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport), dlen);
					 */
					break;
				case IPPROTO_UDP:
					break;
				case IPPROTO_ICMP:
					break;
				case IPPROTO_IP:
					break;
				default:
					printf("Unkown Protocol:%d\n", iphdr->ip_p);
			}
			break;
		default:
			printf("Unkown Type:%d\n", ethhdr->ether_type);
	}
	/*
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
	 */

}

int send_packet(u_int32_t src_ip, u_int16_t src_port, u_int32_t dst_ip, u_int16_t dst_port, u_int32_t seq, u_int32_t ack, u_int32_t payload_s, char *payload) {
	libnet_clear_packet(net_t);
	//TCP
	p_tag = libnet_build_tcp(
			src_port,
			dst_port,
			seq,
			ack,
			TH_RST | TH_ACK,
			0,
			0,
			0,
			LIBNET_TCP_H + payload_s, //LIBNET_TCP_H +  payload_s,
			NULL, //payload
			0, //payload_s
			net_t,
			0);
	if (p_tag == -1) {
		printf("libnet_build_tcp error:%s\n", libnet_geterror(net_t));
		return -1;
	}
	//IP
	u_int16_t len = LIBNET_IPV4_H + LIBNET_TCP_H + payload_s;
	p_tag = libnet_build_ipv4(
			len, /* length */
			0, /* TOS */
			(u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
			0, /* IP Frag */
			111, /* TTL */
			IPPROTO_TCP, /* protocol */
			0, /* checksum */
			src_ip, /* source IP */
			dst_ip, /* destination IP */
			NULL, /* payload */
			0, /* payload size */
			net_t, /* libnet handle */
			0);
	if (p_tag == -1) {
		printf("libnet_build_ipv4 error:%s\n", libnet_geterror(net_t));
		return -1;
	}

	int packet_size;
	packet_size = libnet_write(net_t);
	//printf("packet_size:%d\n", packet_size);
	//libnet_destroy(net_t);
}
