#pragma once

#include <string>
#include <vector>
#include <windows.h>

//parser utility core layout structure
class PEParser {
public:
    //main loop function to process incoming exe targets
    static bool Parse(const std::string& filePath);

private:
    //helper function block to print middle data fields
    static void PrintFileHeader(const IMAGE_FILE_HEADER& fileHeader);
    static void PrintOptionalHeader(const IMAGE_OPTIONAL_HEADER& fileHeader);

    //helper function block to track section properties array data,prints all tables
    static void PrintSectionTable(const std::vector<IMAGE_SECTION_HEADER>& sections);
};