#ifndef FILTERING_H
#define FILTERING_H
#include<fstream>
#include<vector>
#include<string>

using namespace std;
class filtering
{
private:
    string filtered;
    int filteredsize;
    vector<int> getPi(string p);
public:
    bool search(string p);
    filtering(string fname);
};

#endif // FILTERING_H
