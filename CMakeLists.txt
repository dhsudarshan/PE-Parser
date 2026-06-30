cmake_minimum_required(VERSION 3.20)
project(PEParser)

set(CMAKE_CXX_STANDARD 20)

include_directories(include)

add_executable(PEParser
    src/main.cpp
    src/PEParser.cpp
)