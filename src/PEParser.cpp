#include "PEParser.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>

//core parser logic execution start map block
bool PEParser::Parse(const std::string& filePath) {
    //opening file in binary mode
    std::ifstream file(filePath, std::ios::binary);
    //check if file streaming process opened successfully, returns false if file does not exist
    if (!file.is_open()) {
        std::cerr <<"Error: Could not open file: " << filePath << std::endl;
        return false;
    }

    //create storage memory buffer holding standard old dos mz header box
    IMAGE_DOS_HEADER dosHeader;
    //read stream bits into raw dos data pointer variable address location
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    //verify old signature keyword matching, check mz format code tag character
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Error: Invalid DOS Signature (Not a valid executable)." << std::endl;
        return false;
    }

    std::cout << "Valid DOS Header Found." << std::endl;
    //prints offset value in hexadecimal
    std::cout << "PE Header Offset (e_lfanew): 0x" << std::hex << dosHeader.e_lfanew << std::dec << std::endl;

    //moves file pointer to real pe block
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    //create storage box for holding 4 byte pe signature code word
    DWORD peSignature;
    //read target signature field directly from executable file disk stream blocks
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(DWORD));

    //verifies if pe check passes
    if (peSignature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Error: Invalid PE Signature." << std::endl;
        return false;
    }
    std::cout << "Valid PE Signature Found." << std::endl;

    //create empty memory layout instance box, metadata memory allocation
    IMAGE_FILE_HEADER fileHeader;
    //read data into memory address buffer block allocated directly
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER));
    //sends metadata to screen function
    PrintFileHeader(fileHeader);

    //uses seekg to skip optional header
    file.seekg(fileHeader.SizeOfOptionalHeader, std::ios::cur);

    //internal storage section units, allocates dynamic section list
    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    //read block array data elements into vector storage container base sequentially, reads all sections at once
    file.read(reinterpret_cast<char*>(sections.data()), fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    
    //prints the final data table
    PrintSectionTable(sections);

    return true;
}

//displays gathered data on screen
void PEParser::PrintFileHeader(const IMAGE_FILE_HEADER& fileHeader) {
    std::cout << "\n--- COFF FILE HEADER ---" << std::endl;
    std::cout << "    Machine Type:         0x" << std::hex << fileHeader.Machine;
    
    //check if platform machine type is direct 64 bit architecture match logic
    if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) std::cout << " (x64 Native)";
    //check if platform layout points to old legacy 32 bit system model
    else if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386) std::cout << " (x86 Legacy)";
    
    std::cout << std::dec << std::endl;
    //prints total number of sections
    std::cout << "    Number of Sections:   " << fileHeader.NumberOfSections << std::endl;
    //prints creation timestamp integer
    std::cout << "    Time Date Stamp UTC:  " << fileHeader.TimeDateStamp << std::endl;
    //prints size format specs
    std::cout << "    Size of Optional Hdr: " << fileHeader.SizeOfOptionalHeader << " bytes" << std::endl;
}

//loop print function processing continuous section table block objects metadata matrix
void PEParser::PrintSectionTable(const std::vector<IMAGE_SECTION_HEADER>& sections) {
    std::cout << "\n--- SECTION TABLE ---" << std::endl;
    //configure output alignment display width spacing size, control text rendering
    std::cout << std::left << std::setw(12) << "Name" 
              << std::setw(14) << "VirtAddr" 
              << std::setw(14) << "VirtSize" 
              << std::setw(14) << "RawDataPtr" 
              << std::setw(14) << "RawDataSize" << std::endl;
    std::cout << std::string(68, '-') << std::endl;

    //iterate through every single section record row
    for (const auto& section : sections) {
        //setup empty 8 byte character array safety null string container tracking names
        char nameStr[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        //copy raw block label tag name bits directly into clean string storage buffer
        std::memcpy(nameStr, section.Name, IMAGE_SIZEOF_SHORT_NAME);

        //print dynamic metrics data grid track memory size mapping to raw block pointers
        std::cout << std::left << std::setw(12) << nameStr
                  << "0x" << std::setw(12) << std::hex << section.VirtualAddress
                  << "0x" << std::setw(12) << section.Misc.VirtualSize
                  << "0x" << std::setw(12) << section.PointerToRawData
                  << "0x" << std::setw(12) << section.SizeOfRawData << std::dec << std::endl;
    }
}