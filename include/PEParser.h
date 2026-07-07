#pragma once

#include <string>
#include <vector>
#include <windows.h>

//parser utility core layout structure
class PEParser {
public:
    //main loop function to process incoming exe targets
    static bool Parse(const std::string& filePath, const std::string& dumpFile);

private:
    static void PrintFileHeader(const IMAGE_FILE_HEADER& fileHeader);
    static void PrintOptionalHeader(const IMAGE_OPTIONAL_HEADER& fileHeader);
    static void PrintSectionTable(const std::vector<IMAGE_SECTION_HEADER>& sections);
    static void PrintImportTable(std::ifstream& file, const IMAGE_OPTIONAL_HEADER& optionalHeader, std::vector<IMAGE_SECTION_HEADER>& sections);
    static void PrintExportTable(std::ifstream& file, const IMAGE_OPTIONAL_HEADER& optionalHeader, std::vector<IMAGE_SECTION_HEADER>& sections, const std::string& dumpFile);
};