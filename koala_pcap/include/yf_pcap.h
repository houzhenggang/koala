/* 
 * File:   yf_pcap.h
 * Author: Administrator
 *
 * Created on September 9, 2014, 3:47 PM
 */

#ifndef _YF_PCAP_H
#define	_YF_PCAP_H

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
#define ETHER_ADDR_LEN 6

#define P_IP 0x0800
#define P_ARP 0x0806
#define P_RARP 0x8035

/*Ethernet*/
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
/*TCP*/
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;
  u_short th_dport;
  tcp_seq th_seq;
  tcp_seq th_ack;

  u_char th_offx2;
  u_char th_flags;

  u_short th_win;
  u_short th_sum;
  u_short th_urp;
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
#endif	/* YF_PCAP_H */

