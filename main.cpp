#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>


//Ethernet header structure.
struct Ethernet_header{
    u_char D_mac[6];
    u_char S_mac[6];
    u_int16_t Type;
}; //14-Bytes.

//IPv4 header structure.
struct IPv4_header{
    uint8_t version;
    uint8_t protocol;
    uint32_t S_ip;
    uint32_t D_ip;
    uint16_t len;
}; //len-Bytes.

//TCP header structure.
struct TCP_header{
    uint16_t S_port;
    uint16_t D_port;
    uint8_t Data_offset;
}; //Data_offset-Bytes.

struct DATA{
    u_char data[10];
};

void usage() // inform user aobut usage of this application.
{
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct Ethernet_header *set_Ether(const u_char *p) //setup Ethernet header with packet data.
{
    int i = 0;
    struct Ethernet_header *EH = reinterpret_cast<struct Ethernet_header*>(malloc(sizeof(struct Ethernet_header)));
    u_int8_t type[2] = {p[12],p[13]};
    uint16_t *type_in_header = reinterpret_cast<uint16_t *>(type);
    for(i = 0; i < 6; i++)
        EH->D_mac[i] = p[i];
    for(i = 0; i < 6; i++)
        EH->S_mac[i] = p[i + 6];

    EH->Type = ntohs(*type_in_header);
    return EH;
}//Done.

struct IPv4_header *set_ip(const u_char *p) //setup IP header with packet data.
{
    struct IPv4_header *IH = reinterpret_cast<struct IPv4_header*>(malloc(sizeof(struct IPv4_header)));
    uint8_t sip[] = {p[26], p[27], p[28], p[29]};
    uint8_t dip[] = {p[30], p[31], p[32], p[33]};
    uint32_t *sipp = reinterpret_cast<uint32_t *>(sip);
    uint32_t *dipp = reinterpret_cast<uint32_t *>(dip);
    IH->len = p[14] & 0x0f;
    IH->version = p[14] >> 4;
    IH->protocol = p[23];
    IH->S_ip = ntohl(*sipp);
    IH->D_ip = ntohl(*dipp);
    return IH;
}

struct TCP_header *set_tcp(const u_char *p, uint16_t idx) //setup TCP header with packet data.
{
    struct TCP_header *TH = reinterpret_cast<struct TCP_header*>(malloc(sizeof(struct TCP_header)));
    uint16_t index = 14 + (idx * 4);
    uint8_t sprt[] = {p[index], p[index + 1]};
    uint8_t dprt[] = {p[index + 2], p[index + 3]};
    uint8_t offset = p[index + 12] >> 4;
    uint16_t *Sport = reinterpret_cast<uint16_t*>(sprt);
    uint16_t *Dport = reinterpret_cast<uint16_t*>(dprt);
    TH -> S_port = ntohs(*Sport);
    TH -> D_port = ntohs(*Dport);
    TH -> Data_offset = offset;
    return TH;
}

struct DATA *set_data(const u_char *p, struct TCP_header *TCP, struct IPv4_header *IP, unsigned int packet_len)
{
    unsigned int index = 14 + (TCP->Data_offset * 4) + (IP->len * 4);
    unsigned int size = packet_len - index;

    struct DATA *D = reinterpret_cast<struct DATA*>(malloc(sizeof(struct DATA)));

    for(unsigned int i = 0; i < size; i++)
    {
        D->data[i] = p[index + i];
    }

    return D;
}

void print_MACadd(u_char* p) //print MAC address.
{
    for (int i = 0; i < 6; i ++)
    {
        printf("%02x", p[i]);
        if(i < 5)
            printf(":");
    }
    printf("\n");
}

void print_IPadd(uint32_t *p) // print IP address.
{
    uint32_t copp = *p;
    uint8_t add[4];
    for(int i = 3; i > -1; i --)
    {
        add[i] = copp & 0xff;
        copp = copp >> 8;
    }
    printf("%d.%d.%d.%d\n", add[0], add[1], add[2], add[3]);
}

void print_DATA(struct DATA* D)
{
    for (int i = 0; i < 10; i++)
    {
        printf("%02x ",D->data[i]);
    }
    printf("\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {

    //skeleton codes.
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //initialize headers.
    struct Ethernet_header *Ether = set_Ether(packet);
    struct IPv4_header *IP = set_ip(packet);
    struct TCP_header *TCP = set_tcp(packet, IP->len);
    struct DATA *DAT = set_data(packet, TCP, IP, header->caplen);

    //check Network and Transport layer's protocol and if it is not IP && TCP, continue.
    if(Ether->Type != 0x0800 || IP->protocol != 0x06)
    {
        free(TCP);
        free(IP);
        free(Ether);
        continue;
    }
    //print packet's size.
    printf("---------------------------------\n");
    printf("%u bytes captured\n", header->caplen);

    //print MAC addresses of source and destination.
    printf("Source MAC add = ");
    print_MACadd(Ether->S_mac);
    printf("Destination MAC add = ");
    print_MACadd(Ether->D_mac);

    //print IP addresses of source and destination.
    printf("Source IP = ");
    print_IPadd(&IP->S_ip);
    printf("Destination IP = ");
    print_IPadd(&IP->D_ip);

    printf("index : %d\n",IP->len);

    //print Port Number of source and destination.
    printf("Source Port : %d\n",TCP->S_port);
    printf("Destination Port : %d\n",TCP->D_port);

    //print data at most 10 bytes.
    if(*DAT->data != '\x00')
    {
        printf("DATA : ");
        print_DATA(DAT);
    }
    //free malloc()ed structure TCP, IP and Ether.
    free(TCP);
    free(IP);
    free(Ether);
  }
  pcap_close(handle);
  return 0;
}

