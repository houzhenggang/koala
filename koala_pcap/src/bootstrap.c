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
extern void net_demo(char *src_ip_str, char *dst_ip_str, char *dev, char *packet);
extern int check(char *errbuf, char *dev);

int main(int argc, char **argv) {
  pthread_t pid_a; //

  pdt_args_t p_a;
  memset(p_a.errbuf, 0, sizeof (p_a.errbuf));
  memset(p_a.dev, 0, sizeof (p_a.dev));
  memset(p_a.exp, 0, sizeof (p_a.exp));


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
    if (k < argc - 1) strcat(p_a.exp, " ");
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
  pcap_loop(device, -1, callback, (u_char *) & id);
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

  int i;
  for (i = 0; i < pkthdr->len; ++i) {
    printf(" %02x", packet[i]);
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }
  printf("\n\n");

  //ADD
  struct sniff_ethernet *ethernet; //以太网包头
  struct sniff_ip *ip; //ip包头
  struct sniff_tcp *tcp; //tcp包头

  ethernet = (struct sniff_ethernet*) (packet);
  ip = (struct sniff_ip*) (packet + sizeof (struct sniff_ethernet));
  tcp = (struct sniff_tcp*) (packet + sizeof (struct sniff_ethernet) + sizeof (struct sniff_ip));
  printf("From:%s\n", inet_ntoa(ip->ip_src));
  printf("To:%s\n", inet_ntoa(ip->ip_dst));
}

void net_demo(char *src_ip_str, char *dst_ip_str, char *dev, char *packet) {
  libnet_t *net_t = NULL;
  char err_buf[LIBNET_ERRBUF_SIZE];
  libnet_ptag_t p_tag;
  unsigned char src_mac[MAC_ADDR_LEN] = {0x00, 0x00, 0xf1, 0xe8, 0x0e, 0xc8}; //发送者网卡地址

  unsigned char dst_mac[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; //接收者网卡地址

  unsigned long src_ip, dst_ip = 0;
  src_ip = libnet_name2addr4(net_t, src_ip_str, LIBNET_RESOLVE); //将字符串类型的ip转换为顺序网络字节流
  dst_ip = libnet_name2addr4(net_t, dst_ip_str, LIBNET_RESOLVE);
  net_t = libnet_init(LIBNET_LINK_ADV, dev, err_buf); //初始化发送包结构
  if (net_t == NULL) {
    printf("libnet_init error\n");
    exit(0);
  }
  p_tag = libnet_build_icmpv4_echo(
      ICMP_ECHO, /* type */
      0, /* code */
      0, /* checksum */
      0x42, /* id */
      0x42, /* sequence number */
      NULL, /* payload */
      0, /* payload size */
      net_t, /* libnet handle */
      0);
  if (-1 == p_tag) {
    printf("libnet_build_arp error");
    exit(0);
  }

  //以太网头部
  p_tag = libnet_build_ethernet(//create ethernet header
      (u_int8_t *) dst_mac, //dest mac addr
      (u_int8_t *) src_mac, //source mac addr
      ETHERTYPE_ARP, //protocol type
      NULL, //payload
      0, //payload length
      net_t, //libnet context
      0//0 to build a new one
      );

  if (-1 == p_tag) {
    printf("libnet_build_ethernet error!\n");
    exit(-1);
  }
  int res;
  if (-1 == (res = libnet_write(net_t))) {
    printf("libnet_write error!\n");
    exit(1);
  }

  libnet_destroy(net_t);
}
