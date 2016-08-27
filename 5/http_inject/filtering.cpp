#include<iostream>
#include<vector>
#include<string.h>
#include<unistd.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<fcntl.h>
#include "filtering.h"
using namespace std;
filtering::filtering(char* fname)
{
    if((fd = open(fname,O_RDONLY)) < 0)
    {
        cout << "[!] open " << endl;
        return;
    }
    filteredsize = lseek(fd,0,SEEK_END);
    if((filtered = (char*)mmap(NULL,filteredsize,PROT_READ,MAP_SHARED,fd,0)) < 0)
    {
        cout << "[!] mmap " << endl;
    }
}

filtering::~filtering(void)
{
    munmap(filtered,filteredsize);
    close(fd);
}

vector<int> filtering::getPi(char* p)
{
    int i,j,n;
    n=strlen(p);
    vector<int> pi(n,0);
    for(i=1,j=0;i<n;i++)
    {
        while(j>0 && p[i] != p[j])
            j=pi[j-1];
        if(p[i] == p[j])
            pi[i] = ++j;
    }
    return pi;
}
uint32_t filtering::search(char* p,char* s,uint32_t off)
{
    vector<int> pi = getPi(p);
    int i,j,n,m;
    n=strlen(s);
    m=strlen(p);
    for(i=off,j=0;i<n;i++)
    {
        while(j>0 && s[i] != p[j])
            j=pi[j-1];
        if(s[i] == p[j])
        {
            if(j==m-1)
                return i;
            else
                j++;
        }
    }
    return -1;
}
bool filtering::searchfi(char* p)
{
    if(search(p,filtered,0) == -1)
        return false;
    else
        return true;
}
