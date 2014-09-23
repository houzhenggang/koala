/* 
 * File:   yf_pcap.h
 * Author: yafengli@sina.com
 *
 */

#ifndef _YF_PCAP_H
#define  _YF_PCAP_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define TRUE 1
#define FALSE -1

#define P_IP 0x0800
#define P_ARP 0x0806
#define P_RARP 0x8035

/*libnet use*/
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

/*Ethernet*/
#define SIZE_ETHERNET 14

struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN];
  u_char ether_shost[ETHER_ADDR_LEN];
  u_short ether_type;
};

/*IP*/
struct sniff_ip {
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
  u_char ip_ttl;
  u_char ip_p;
  u_short ip_sum;
  struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
/*TCP*/
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq; /* sequence number */
  tcp_seq th_ack; /* acknowledgement number */
  u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

/*UDP*/
struct sniff_udp {
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_len;
  u_short udp_sum;
};

/*DNS*/
struct sniff_dns {
  u_short dns_id;
  u_short dns_flag;
  u_short dns_ques;
  u_short dns_ans;
  u_short dns_auth;

  u_short dns_add;
  u_int8_t *dsn_data;
};

/*PTHREAD STRUCTOR*/
#define PTHREAD_ARG_LEN 256

typedef struct pdt_args {
  char errbuf[PCAP_ERRBUF_SIZE];
  char in_dev[PTHREAD_ARG_LEN];
	char out_dev[PTHREAD_ARG_LEN];
  char exp[PTHREAD_ARG_LEN];
} pdt_args_t;
#endif	/* YF_PCAP_H */

