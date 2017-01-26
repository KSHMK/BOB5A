#ifndef DEAUTHER_H
#define DEAUTHER_H
#include<tins/tins.h>
#include<iostream>
#include<string>
using namespace std;
using namespace Tins;

class Deauther{
private:
    NetworkInterface iface;
    HWAddress<6> AP,Station;
public:
    Deauther(string _iface,string _AP,string _Station);
    void Start(void);
    int GetFreq(void);
};

#endif // DEAUTHER_H
