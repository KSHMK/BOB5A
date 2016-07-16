#include<iostream>
#include<pcap/pcap.h>
#include"arpconfuser.h"
using namespace std;



int main(int argc,char* argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

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

    ARPConfuser arpc(dev,argv[1]);
    arpc.startcorrupt();
    return 0;

}
