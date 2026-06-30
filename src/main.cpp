#include "PEParser.h"
#include <iostream>

//application console loop setup runner starting coordinate point tracking runtime logic, entry point trigger
int main(int argc, char* argv[]) {
    //check if user typed terminal command argument target path data string field, validates execution argument count
    if (argc < 2) {
        std::cout << "Usage Error: " << argv[0] << " <path_to_windows_binary.exe>" << std::endl;
        return 1;
    }

    //path string storage
    std::string targetFile = argv[1];
    std::cout << "[*] Starting analysis on file: " << targetFile << "\n" << std::endl;

    //executes parsing core flow
    if (!PEParser::Parse(targetFile)) {
        std::cerr << "[-] Extraction processing failed." << std::endl;
        return -1;
    }

    std::cout << "\n[+] Extraction successfully completed." << std::endl;
    return 0;
}