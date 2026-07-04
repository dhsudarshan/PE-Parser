#include "PEParser.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage Error: " << argv[0] << " <path_to_windows_binary.exe>" << std::endl;
        return 1;
    }

    std::string targetFile = argv[1];
    std::cout << " Starting analysis on file: " << targetFile << "\n" << std::endl;

    if (!PEParser::Parse(targetFile)) {
        std::cerr << " Extraction processing failed." << std::endl;
        return -1;
    }

    std::cout << "\n Extraction successfully completed." << std::endl;
    return 0;
}