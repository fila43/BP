#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc <2)
        return 1;

    std::ifstream myfile;
    myfile.open(argv[1]);
    std::string line;
    std::ofstream out_file;
    out_file.open (std::string(argv[1])+".data", std::ofstream::out | std::ofstream::binary);




    while(std::getline(myfile,line)) {
        line.erase(0, 6);
        unsigned long delka = line.length();
        unsigned long i;
        for (unsigned long j = 0, i = 0; i < line.length(); j++, i = i + 2) {
            if (j % 2 == 0) {
                i++;
            }
            if (i >= delka) {

                break;
            }
            delka--;

        }

        line.erase(line.begin() + delka, line.end());
        for (unsigned long i=0; i<line.length();i++){
            if (!isalnum(line[i])) {
                line.erase(line.begin() + i, line.begin() + i + 1);
                i--;
            }
        }
        out_file << line;
    }
        out_file.close();
        return 0;

}
