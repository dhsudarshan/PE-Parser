#include "PEParser.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage Error: " << argv[0] << " <path_to_windows_binary.exe>" << std::endl;
        return 1;
    }
    std::string dumpFile = "";
    if(argc > 2){
        std::string flag = argv[2];
        if(flag == "-a" || flag == "--all")
            if(argc<4){
                std::cout << "Expected filepath after flag " << flag;
                return -1;
            }
        dumpFile = argv[3];
    }

    std::string targetFile = argv[1];
    std::cout << "Starting analysis on file: " << targetFile << "\n" << std::endl;
    
    if (!PEParser::Parse(targetFile, dumpFile)) {
        std::cerr << "Extraction processing failed." << std::endl;
        return -1;
    }

    std::cout << "\nExtraction successfully completed." << std::endl;
    return 0;
}