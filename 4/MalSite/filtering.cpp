#include<fstream>
#include<vector>
#include<string>
#include "filtering.h"
using namespace std;
filtering::filtering(string fname)
{
    ifstream fp(fname);
    while(!fp.eof())
        filtered.push_back(fp.get());
    filteredsize = filtered.size()
}

vector<int> filtering::getPi(string p)
{
    int i,j,n;
    n=p.size();
    vector<int> pi(m,0);
    for(i=1,j=0;i<n;i++)
    {
        while(j>0 && p[i] != p[j])
            j=pi[j-1];
        if(p[i] == p[j])
            pi[i] = ++j;
    }
    return pi;
}
bool filtering::search(string p)
{
    vector<int> pi = getPi(p);
    int i,j,n,m;
    n=filteredsize;
    m=p.size();
    for(i=0,j=0;i<n;i++)
    {
        while(j>0 && s[i] != p[j])
            j=pi[j-1];
        if(s[i] == p[j])
        {
            if(j==m-1)
                return true;
            else
                j++;
        }
    }
    return false;
}
