#ifndef FILTERING_H
#define FILTERING_H
#include<fstream>
#include<vector>

using namespace std;
class filtering
{
private:
    int fd;
    char* filtered;
    int filteredsize;
    vector<int> getPi(char* p);
public:
    uint32_t search(char* p,char* s,uint32_t off);
    bool searchfi(char* p);
    filtering(char* fname);
    ~filtering(void);
};

#endif // FILTERING_H
