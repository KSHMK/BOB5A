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

#pragma pack(pop)
#define BUFSIZE 0x20000

