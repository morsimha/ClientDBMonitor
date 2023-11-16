/*
CRC32.h
*/

#pragma once
#include <cstdint>
#include <string>

class CRC32 {
private:
	uint32_t crc;
	uint32_t nchar;

public:
	CRC32();
	~CRC32();
	void update(unsigned char*, uint32_t);
	uint32_t digest();
	uint32_t calcCrc(std::string);
};