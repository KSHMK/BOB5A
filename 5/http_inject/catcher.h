#ifndef CATCHER_H
#define CATCHER_H
#include<arpa/inet.h>
#include<vector>
#include<thread>
using namespace std;
class ARPSpoofer{
private:
    const char* dev;
    uint8_t Myhwaddr[6];
    uint8_t TXhwaddr[6];
    uint8_t RXhwaddr[6];
    struct in_addr Myipaddr;
    struct in_addr TXipaddr;
    struct in_addr RXipaddr;
    bool state;
    void recvarp(in_addr *srcip, uint8_t *srchw,\
                 in_addr *dstip, uint8_t *dsthw, const char* filter);
    void sendarp(struct in_addr* srcip,uint8_t* srchw,\
                 struct in_addr* dstip,uint8_t* dsthw);
    void relayingpacket(pcap_t* handle, uint8_t* dsthw, uint8_t* srchw);
public:

    vector<thread> th;
    void getmyaddr(void);
    void gethwaddr(struct in_addr* targetip,uint8_t* targethw);
    void startrelay(void);
    void startarpspoofing(void);
    void stoparpspoofing(void);

    ARPSpoofer(const char* dev,const char* txipaddr,const char* rxipaddr);

};

#endif // CATCHER_H
