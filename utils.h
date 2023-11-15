/*
utils.h
*/

#pragma once
#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>


class utils {
public:
	bool openFile(const std::string&, std::fstream&, bool);
	bool openBinaryFile(const std::string&, std::fstream&, bool);
	bool OverwriteFile(const std::string&, std::fstream&);
	bool closeFile(std::fstream&);
	bool writeToFile(std::fstream&, const char*, uint32_t);
	bool readFileIntoBuffer(std::fstream&, char*, uint32_t);
	bool bufferToHexFile(std::fstream&, const char*, unsigned int);

	bool isExist(const std::string&);
	uint32_t getSize(const std::string&);
};

