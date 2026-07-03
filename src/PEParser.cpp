#include "PEParser.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>

bool PEParser::Parse(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr <<"Error: Could not open file: " << filePath << std::endl;
        return false;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    //every PE file has image dos signature 'MZ'
    //if it is missing, file is not valid executable
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Error: Invalid DOS Signature (Not a valid executable)." << std::endl;
        return false;
    }

    std::cout << "Valid DOS Header Found." << std::endl;
    
    //e_lfanew stores the file offset of the PE (NT) headers.
    std::cout << "PE Header Offset (e_lfanew): 0x" << std::hex << dosHeader.e_lfanew << std::dec << std::endl;

    //seek to the PE (NT) headers using the offset stored in e_lfanew.
    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    //4 byte pe signature(PE/0/0) immediately preceeds NT headers 
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(DWORD));

    //PE signature confirms valid NT headers exist
    if (peSignature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Error: Invalid PE Signature." << std::endl;
        return false;
    }
    std::cout << "Valid PE Signature Found." << std::endl;

    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER));
    
    PrintFileHeader(fileHeader);
    
    IMAGE_OPTIONAL_HEADER64 optionalHeader;
    
    file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(IMAGE_OPTIONAL_HEADER));
    PrintOptionalHeader(optionalHeader);

    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    

    PrintSectionTable(sections);

    return true;
}

void PEParser::PrintFileHeader(const IMAGE_FILE_HEADER& fileHeader) {
    std::cout << "\n--- COFF FILE HEADER ---" << std::endl;
    std::cout << "    Machine Type:         0x" << std::hex << fileHeader.Machine;
    
    //machine field identifies target processor architecture
    if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) std::cout << " (x64)";
    else if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386) std::cout << " (x86)";
    
    std::cout << std::dec << std::endl;
    std::cout << "    Number of Sections:   " << fileHeader.NumberOfSections << std::endl;
    std::cout << "    Time Date Stamp UTC:  " << fileHeader.TimeDateStamp << std::endl;
    std::cout << "    Size of Optional Hdr: " << fileHeader.SizeOfOptionalHeader << " bytes" << std::endl;

}


void PEParser::PrintOptionalHeader(const IMAGE_OPTIONAL_HEADER& optionalHeader){
    std::cout << " --- OPTIONAL HEADERS --- " << std::endl;
    std::cout<< "   PE Format Type:   " << std::hex <<optionalHeader.Magic;

    //magic field identifies whether optionalHeader uses PE32 or PE32+ format
    if(optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC){ std::cout << " (PE32)";}
    else if(optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC){ std::cout << " (PE32+)";}



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