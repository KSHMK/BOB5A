#ifndef ARPSPOOOFER_H
#define ARPSPOOFER_H
#include<arpa/inet.h>
class ARPSpoofer{
private:
    const char* dev;
    uint8_t Myhwaddr[6];
    uint8_t TXhwaddr[6];
    uint8_t RXhwaddr[6];
    struct in_addr Myipaddr;
    struct in_addr TXipaddr;
    struct in_addr RXipaddr;
    static void recvarp(const char* dev,in_addr *srcip, uint8_t *srchw,\
                        in_addr *dstip, uint8_t *dsthw, const char* filter);
    void sendarp(struct in_addr* srcip,uint8_t* srchw,\
                 struct in_addr* dstip,uint8_t* dsthw);
    static void intelligentsendarp(pcap_t* rhandle, pcap_t* shandle, u_char* sendpacket);
    static void relayingpacket(pcap_t* handle, uint8_t* dsthw );
public:
    void getmyaddr(void);
    void gethwaddr(struct in_addr* targetip,uint8_t* targethw);
    void startcorrupt(void);
    void startrelay(void);
    void startarpspoofing(void){
        startcorrupt();
        startrelay();
    }

    ARPSpoofer(const char* dev,const char* txipaddr,const char* rxipaddr);
};

#endif // ARPSPOOFER_H
