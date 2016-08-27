/*==================================================
    Made By KSHMK
    asdf7845120.gmail.com
    Copyright for KSHMK
==================================================*/
#include<stdint.h>
#pragma pack(push,1)
typedef struct ether_header {
#define ETH_ALEN 6
    uint8_t eth_dst[ETH_ALEN];
    uint8_t eth_src[ETH_ALEN];
#define ETHERTYPE_PUP	0x0200
#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_ARP	0x0806
#define ETHERTYPE_REARP 0x8035
    uint16_t eth_type;
}ether_header;

typedef struct arp_header {
    uint16_t arp_htype;
#define ARP_ETHER 0x0001
    uint16_t arp_ptype;
#define ARP_IP 0x0800
    uint8_t arp_hlen;
#define ARP_ETHERL 0x06
    uint8_t arp_plen;
#define ARP_IPL 0x04
    uint16_t arp_op;
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
    uint8_t arp_srhaddr[ARP_ETHERL];
    uint32_t arp_srpaddr;
    uint8_t arp_desthaddr[ARP_ETHERL];
    uint32_t arp_destpaddr;
}arp_header;

typedef struct ip_header {
    uint8_t ip_hi:4;
    uint8_t ip_vi:4;
#define IP_VER_IP4 0x4
#define IP_DEFAUL_HDR_LEN 0x5
    uint8_t ip_tos;
#define IP_TOS_DEFALT 0x0
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
#define IP_FRAG_DF 0x4000
#define IP_FRAG_MF 0x2000
#define IP_OFFMASK 0x1FFF

    uint8_t ip_ttl;
#define IP_TTL_DEFALT 0x80
    uint8_t ip_p;
#define IP_PROTO_TCP 0x6
#define IP_PROTO_UDP 0x11

    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
#define IP_ADDR_LEN 0x4
}ip_header;

typedef struct pseudo_header{
    uint32_t ps_sraddr;
    uint32_t ps_destaddr;
    uint8_t ps_reserve;
    uint8_t ps_protocol;
    uint16_t ps_seglen;
}pseudo_header;

typedef struct tcp_header {
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seqnum;
    uint32_t tcp_acknum;
    uint8_t tcp_hlen;
#define TCP_DEFAULT_HLEN 0x20
    uint8_t tcp_reserve;
    uint8_t tcp_flag;
#define TCP_FLAG_CWR 0x10000000
#define TCP_FLAG_ECE 0x1000000
#define TCP_FLAG_URG 0x100000
#define TCP_FLAG_ACK 0x10000
#define TCP_FLAG_PSH 0x1000
#define TCP_FLAG_RST 0x100
#define TCP_FLAG_SYN 0x10
#define TCP_FLAG_FIN 0x1
    uint16_t tcp_win;
    uint16_t tcp_sum;
    uint16_t tcp_urgptr;
}tcp_header;

#pragma pack(pop)
#define BUFSIZE 0x20000

