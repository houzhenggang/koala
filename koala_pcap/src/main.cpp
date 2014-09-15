#include <iostream>
#include <cmath>
#include "hello"


extern "C" {
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "yf_trim.h"
}

using namespace std;
using namespace hello;

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
        printf("device:%d name:%s desc:%s\n", ++i, alldevs->name, alldevs->description);

        bpf_u_int32 netp; //ip
        bpf_u_int32 maskp; //subnet mask
        int ret; //return code
        ret = pcap_lookupnet(dev, &netp, &maskp, errBuf);
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

int main(int argc, char **argv) {
  cout << "Hello, World!" << endl;
  stu stu_1;
  score sco_1;
  cout << stu_1.add(111, 222) << endl;
  cout << sco_1.add(222, 333) << endl;

  my_class<int, int> my_class1(1, 3);
  my_class1.show();


  if (argc < 3) {
    printf("Usage:command -i [dev name] [expression]\n");
    exit(-1);
  }

  char errBuf[PCAP_ERRBUF_SIZE];
  memset(errBuf, 0, sizeof(errBuf));
  char *dev = (char *) malloc(OPTION_BUF_LEN);
  char exp[1024];
  cout << "exp len:" << sizeof(exp) << endl;
  memset(exp, 0, sizeof(exp));
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
          cout << "expression:" << exp << endl;
          loop_dev(errBuf, dev, exp, getPacket);
          break;
        default:
          printf("Usage:command -i [eth_name]");
      }
    }
  }
  free(dev);
  return 0;
}
