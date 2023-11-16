#include "utils.h"


// Check if a file exists at the given path.
bool utils::isExist(const std::string& fileDestination)
{
	std::filesystem::path pathToCheck = fileDestination;
	return std::filesystem::exists(fileDestination);
}

// returns the size of a file in bytes.
uint32_t utils::getSize(const std::string& fileDestination)
{
	std::filesystem::path pathToCheck = fileDestination;
	return std::filesystem::file_size(pathToCheck);
}

// Open a file for reading or writing, creating directories if needed.
bool utils::openFile(const std::string& fileDestination, std::fstream& thisFile, bool writeFlag)
{

	if (!isExist(fileDestination)) {
		std::cerr << "Error:  "<< fileDestination << " doesn't exist. Cannot retrieve file name. " << std::endl;
		return false;
	}

	try {
		std::filesystem::create_directories(std::filesystem::path(fileDestination).parent_path());
		auto flag = writeFlag ? (std::fstream::out | std::fstream::app) : std::fstream::in;
		thisFile.open(fileDestination, flag);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Open file exception for " << fileDestination << ": " << e.what() << std::endl;
		return false;
	}
}

// Opens a binary file
bool utils::openBinaryFile(const std::string& fileDestination, std::fstream& thisFile, bool writeFlag)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flags = writeFlag ? (std::fstream::binary | std::fstream::out) : (std::fstream::binary | std::fstream::in);
		thisFile.open(fileDestination.c_str(), flags);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

// overwrites the content.
bool utils::OverwriteFile(const std::string& fileDestination, std::fstream& thisFile)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flag = std::fstream::binary | std::fstream::out | std::fstream::trunc;
		thisFile.open(fileDestination.c_str(), flag);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

// Read a specific number of bytes from a file into the buffer buffer.
bool utils::readFileIntoBuffer(std::fstream& thisFile, char* buffer, uint32_t count)
{
	try {
		thisFile.read(buffer, count);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

// Write content to an open file.
bool utils::writeToFile(std::fstream& thisFile, const char* content, uint32_t size)
{
	if (!thisFile.is_open() || content == nullptr || size == 0) {
		std::cerr << "Invalid input for writeToFile." << std::endl;
		return false;
	}

	try {
		thisFile.write(content, size);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Write to file exception: " << e.what() << std::endl;
		return false;
	}
}

// Close an open file.
bool utils::closeFile(std::fstream& thisFile)
{
	try {
		thisFile.close();
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

/* Given a buffer, writes the buffer in hex into a file. (Inspired by the code provided by the lecturers, w/ small tweaks)*/
bool utils::bufferToHexFile(std::fstream& thisFile, const char* buffer, unsigned int length)
{
	std::ios::fmtflags f(thisFile.flags());
	thisFile << std::hex;
	try {
		for (size_t i = 0; i < length; i++)
			thisFile << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);
		thisFile.flags(f);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Failed to hex: " << e.what() << std::endl;
		return false;
	}

}

