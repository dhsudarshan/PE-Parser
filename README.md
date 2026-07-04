# PE-Parser

A lightweight Portable Executable (PE) parser written in modern C++.

This project is a personal learning project to help me in understanding the Windows Portable Executable (PE) file format by parsing executable files manually instead of relying on existing libraries.

The goal is to gradually build a feature-complete PE parser while learning about Windows internals, binary file formats, and low-level systems programming.

---

## Current Features

- Reads PE files directly from disk
- Validates the DOS (`MZ`) header
- Locates the PE header using `e_lfanew`
- Validates the NT (`PE\0\0`) signature
- Parses and displays the COFF File Header
- Optional Header parsing
- Parses and displays the Section Table
- Human-readable console output
- Data Directory parsing
- Import Table parsing

---

## Planned Features

- [ ] Export Table parsing
- [ ] Resource Directory parsing
- [ ] Base Relocations
- [ ] TLS Directory
- [ ] Debug Directory
- [ ] RVA ↔ File Offset conversion
- [ ] Section characteristics decoding
- [ ] Better error handling
- [ ] JSON output mode


---

## Building

### Prerequisites

- C++20 compatible compiler
- CMake 3.20 or later
- Windows

### Using CMake (MSVC / Visual Studio)

```bash
git clone https://github.com/dhsudarshan/PE-Parser.git
cd PE-Parser

cmake -S . -B build
cmake --build build
```

### Using CMake with MinGW-w64 (g++)

If you are using MinGW-w64 instead of MSVC, specify the MinGW generator:

```bash
git clone https://github.com/dhsudarshan/PE-Parser.git
cd PE-Parser

cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

> **Note:** If you previously configured the project with a different generator (for example, NMake or Visual Studio), delete the existing `build` directory before re-running CMake to avoid generator conflicts.

## Usage

```bash
PE-Parser.exe <path_to_executable>
```

Example

```bash
PE-Parser.exe C:\Windows\System32\notepad.exe
```

---

## Project Structure

```
PE-Parser/
│
├── include/
│   └── PEParser.h
│
├── src/
│   ├── main.cpp
│   └── PEParser.cpp
│
├── CMakeLists.txt
└── README.md
```

---

## Learning Goals

This project is intended to deepen my understanding of:

- Windows PE format
- Binary parsing
- Windows executable layout
- Modern C++
- Reverse engineering fundamentals
- Systems programming

---

## References

- Microsoft PE/COFF Specification
- Windows Internals