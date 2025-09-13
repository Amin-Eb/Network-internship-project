#include "DnsAnalyzer.h"
#include <iostream>

using namespace std; 

int main() {
    auto stats = processPcap("../samples/capture.pcapng");
    if(stats.errorcode == 0){
        cout << "Successful answers: " << stats.successful << endl;
        cout << "Failed answers: " << stats.unsuccessful << endl;
        cout << "RATIO IS -> " << ((1.0 * stats.successful)/(1.0 *stats.successful + 1.0 * stats.unsuccessful) * 100.0) << "%" << endl;
    }
    return 0;
}
