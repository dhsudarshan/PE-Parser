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
    
    IMAGE_IMPORT_DESCRIPTOR importTable;
    file.read(reinterpret_cast<char*>(&importTable), sizeof(IMAGE_IMPORT_DESCRIPTOR));
    PrintImportTable(file, optionalHeader ,sections);
    return true;
}

//convert relative virtual address to file offset
DWORD rvaToOffset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections){
    for(auto& section : sections){
        if(rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize){
            return rva - section.VirtualAddress + section.PointerToRawData;
        }
    }
    return 0;
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
    std::cout << "   PE Format Type:   " << std::hex <<optionalHeader.Magic;

    //magic field identifies whether optionalHeader uses PE32 or PE32+ format
    if(optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC){ std::cout << " (PE32)" << std::endl;;}
    else if(optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC){ std::cout << " (PE32+)" << std::endl;}
    else{ std::cout << " Unrecognized file format" << std::endl;}

    //address of entry point is relative virtual address of entry point when file is loaded into memory
    std::cout << "   Address of Entry Point:   " << optionalHeader.AddressOfEntryPoint << std::endl;

    //image base defines preferred memory address file would like to be loaded onto. 
    std::cout << "   ImageBase:   " << optionalHeader.ImageBase << std::endl;

    std::cout << "   Size of Image:   " << optionalHeader.SizeOfImage << std::endl;

    std::cout << "   Size of Code:   " << optionalHeader.SizeOfCode << std::endl;
}

void PEParser::PrintSectionTable(const std::vector<IMAGE_SECTION_HEADER>& sections) {
    std::cout << "\n--- SECTION TABLE ---" << std::endl;
    std::cout << std::left << std::setw(12) << "Name" 
              << std::setw(14) << "VirtAddr" 
              << std::setw(14) << "VirtSize" 
              << std::setw(14) << "RawDataPtr" 
              << std::setw(14) << "RawDataSize" << std::endl;
    std::cout << std::string(68, '-') << std::endl;

    for (const auto& section : sections) {
        char nameStr[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        std::memcpy(nameStr, section.Name, IMAGE_SIZEOF_SHORT_NAME);

        std::cout << std::left << std::setw(12) << nameStr
                  << "0x" << std::setw(12) << std::hex << section.VirtualAddress
                  << "0x" << std::setw(12) << section.Misc.VirtualSize
                  << "0x" << std::setw(12) << section.PointerToRawData
                  << "0x" << std::setw(12) << section.SizeOfRawData << std::dec << std::endl;
    }
}
void PEParser::PrintImportTable(std::ifstream& file, const IMAGE_OPTIONAL_HEADER& optionalHeader, std::vector<IMAGE_SECTION_HEADER>& sections){
    //import table rva is in data directory of optional header(index 1)
    DWORD importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importOffset = rvaToOffset(importRVA, sections);

    IMAGE_IMPORT_DESCRIPTOR descriptor;
    file.seekg(importOffset, std::ios::beg);

    while (true) {
        file.read(reinterpret_cast<char*>(&descriptor), sizeof(descriptor));
        if (descriptor.Name == 0) break; 
        auto savedPos = file.tellg();
        file.seekg(rvaToOffset(descriptor.Name, sections), std::ios::beg);
        
        char dllName[256] = {0};
        file.read(dllName, sizeof(dllName));
        std::cout << "DLL: " << dllName << std::endl;
        
        file.seekg(savedPos, std::ios::beg);
}
}