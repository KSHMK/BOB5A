#ifndef ARPCONFUSER_H
#define ARPCONFUSER_H
#include<arpa/inet.h>
class ARPConfuser{
private:
    const char* dev;
    uint8_t Myhwaddr[6];
    uint8_t TXhwaddr[6];
    uint8_t RXhwaddr[6];
    struct in_addr Myipaddr;
    struct in_addr TXipaddr;
    struct in_addr RXipaddr;
    static void recvarp(const char* dev,in_addr *srcip, uint8_t *srchw,\
                        in_addr *dstip, uint8_t *dsthw);
    void sendarp(struct in_addr* srcip,uint8_t* srchw,\
                 struct in_addr* dstip,uint8_t* dsthw);
public:
    void getmyaddr(void);
    void gethwaddr(struct in_addr* targetip,uint8_t* targethw);
    void startcorrupt(void);
    ARPConfuser(const char* dev,const char* txipaddr);
};

#endif // ARPCONFUSER_H
