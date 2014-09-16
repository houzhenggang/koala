#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <ctype.h>
#include <yf_trim.h>
#include <yf_pcap.h>

typedef struct sniff_ethernet ethernet;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
  int * id = (int *) arg;

  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *) &pkthdr->ts.tv_sec));

  int i;
  for (i = 0; i < pkthdr->len; ++i) {
    printf(" %02x", packet[i]);
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }
  printf("\n\n");
}

int check_pkt(ethernet *eth) {
  if (eth == NULL) {
    return FALSE;
  } else {
    int i;
    for (i = 0; i <= 5; i++) {
      printf("%.2X:", eth->ether_shost[i]);
    }
    printf("\n");
    for (i = 0; i <= 5; i++) {
      printf("%.2X:", eth->ether_dhost[i]);
    }
    printf("\n");
    return TRUE;
  }
}

void packet_info(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
  int *id = (int *) arg;
  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *) &pkthdr->ts.tv_sec));

  ethernet *eth;
  struct sniff_ip *ip;
  struct sniff_tcp *tcp;
  struct sniff_udp *udp;
  struct sniff_dns *dns; //dns报头
  const char *payload;
  int pay_size; //

  eth = (ethernet *) packet;
  if (check_pkt(eth) == -1) {
    printf("Get Error.\n");
    exit(-1);
  }

  switch (ntohs(eth->ether_type)) {
    case P_IP:
      printf("IP");
      break;
    case P_ARP:
      printf("ARP");
      break;

  }
  //
  //	ip = (struct sniff_ip *) (packet + sizeof(struct sniff_ethernet));
  //	udp = (struct sniff_udp *) (packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
  //	dns = (struct sniff_dns*) (packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) + sizeof(struct sniff_udp));
  //	payload = (u_char *) (packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) + sizeof(struct sniff_udp) + sizeof(struct sniff_dns));
  //	pay_size = ntohs(udp->udp_len) - sizeof(struct sniff_udp) - sizeof(struct sniff_dns);
  //	printf("-------------数据包:%d\n", pay_size);
  //	printf("数据包类型：%s\n", eth->ether_type);
  //	printf("源地址：%X:%X:%X:%X:%X:%X\N", (eth->ether_shost)[0], (eth->ether_shost)[1], (eth->ether_shost)[2], (eth->ether_shost)[3], (eth->ether_shost)[4],
  //			(eth->ether_shost)[5]);
  //	printf("目标地址：%X:%X:%X:%X:%X:%X\N", (eth->ether_dhost)[0], (eth->ether_dhost)[1], (eth->ether_dhost)[2], (eth->ether_dhost)[3], (eth->ether_dhost)[4],
  //			(eth->ether_dhost)[5]);
  //
  //	printf("From:%s\n", inet_ntoa(ip->ip_src));
  //	printf("To:%s\n", inet_ntoa(ip->ip_dst));
  //	printf("源端口:%s\n", ntohs(udp->udp_sport));
  //	printf("目标端口:%s\n", ntohs(udp->udp_dport));
}

void call(char *devStr, char *errBuf, pcap_handler callback) {
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);

  if (!device) {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }

  struct bpf_program filter;
  pcap_compile(device, &filter, "host 172.16.83.1", 1, 0);
  pcap_setfilter(device, &filter);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, callback, (u_char*) & id);
  pcap_close(device);
}

void s_loop_dev(char *err, pcap_handler callback) {
  char *devStr;
  /* get a device */
  devStr = pcap_lookupdev(err);
  if (devStr) {
    printf("success device: %s\n", devStr);
  } else {
    printf("error device.");
  }
}

void loop_dev(char *errBuf, char *dev, pcap_handler callback) {
  pcap_if_t *alldevs;

  if (pcap_findalldevs(&alldevs, errBuf) == 0) {
    int i = 0;
    for (; alldevs != NULL; alldevs = alldevs->next) {
      if (strcmp(alldevs->name, dev) == 0) {
        printf("device:%d name:%s desc:%s\n", ++i, alldevs->name, alldevs->description);

        bpf_u_int32 netp; //ip
        bpf_u_int32 maskp; //subnet mask
        int ret; //return code
        ret = pcap_lookupnet(dev, &netp, &maskp, errBuf);
        call(alldevs->name, errBuf, callback);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage:command -i [device name]\n");
    exit(-1);
  }

  char errBuf[PCAP_ERRBUF_SIZE];
  int i;
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-' || argv[i][0] == '/') {
      char *opt = (char *) malloc(OPTION_BUF_LEN);
      switch (tolower(argv[i][1])) {
        case 'i':
          trim(argv[++i], opt);
          //				loop_dev(errBuf, opt, getPacket);
          loop_dev(errBuf, opt, packet_info);
          break;
        default:
          printf("Usage:command -i [eth_name]");
      }
      free(opt);
    }
  }
  return 0;
}
