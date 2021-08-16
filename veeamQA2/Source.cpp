#include "HashChk.h"

#include <iostream>
#include <string>
#include <iomanip>

using namespace std;
using namespace Hshchk;

int main(int argc, char* argv[]) {
    if (argc == 3) {
        HashChk main{argv[1], argv[2]};
        try {
            main.parseSrcFile();
            main.calculateDstFiles();
            main.printResults();
        } catch (...) {
            cerr << "Something with src goes wrong" << endl;
        }
    } else {
        cerr << "Write correct paths - src file and dst folder" << endl;
        return 1;
    }
    return 0;
}
