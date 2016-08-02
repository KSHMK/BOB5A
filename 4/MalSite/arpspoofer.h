#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H
#include<tins/tins.h>
#include<vector>
#include<thread>
using namespace std;
using namespace Tins;
class ARPSpoofer {
public:
    ARPSpoofer(const char* txipaddr, const char* rxipaddr);
    void startarpspoofing(void);
    void stoparpspoofing(void);
private:
    void startcorrupt(void);
    void startrelay(void);
    void intelsendarp(void);
    void timersendarp(void);
    void relayingpacket(void);

    bool status;
    vector<thread> threads;
    EthernetII::address_type Myhwaddr,TXhwaddr,RXhwaddr;
    IPv4Address Myipaddr,TXipaddr,RXipaddr;
    NetworkInterface iface;
};

#endif // ARPSPOOFER_H
