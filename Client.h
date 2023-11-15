/*
Client.h
*/

#pragma once
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <string>
#include "utils.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "CRC32.h"
#include "NetworkProtocol.h"



#define PACKET_SIZE 1024
#define USER_LENGTH 255
#define ME_INFO "./me.info"
#define TRANSFER_INFO "./transfer.info"
#define PRIV_KEY "./priv.key"
#define PUB_KEY_LEN 160
#define AES_KEY_LEN 16
#define AES_BLOCK_SIZE 16
#define CLIENT_ID_SIZE 16
#define FILE_NAME_LEN 255
#define TRANSFER_LINES 3
#define PRIV_KEY_LINES 12
#define ENC_AES_LEN 128
#define MAX_TRIES 3


class Client {

	// Unified function to update ME_INFO file based on the operation type
	bool addPrivkeyToMeFile(utils fileUtils, std::string& encoded_privkey) const;
	bool addUserToMeFile(utils fileUtils, std::string& username, ClientResponse& res, char* uuid) const;
	enum Request_Code { REGISTER_REQUEST = 1025, PUB_KEY_SEND = 1026, LOGIN_REQUEST = 1027, FILE_SEND = 1028, CRC_OK = 1029, CRC_INVALID_RETRY = 1030, CRC_INVALID_EXIT = 1031 };
	enum Response_Code { REGISTER_SUCCESS = 2100, REGISTER_ERROR = 2101,PUB_KEY_RECEVIED = 2102, FILE_OK_CRC = 2103, MSG_RECEIVED = 2104, LOGIN_SUCCESS = 2105, LOGIN_ERROR = 2106, GENERAL_ERROR = 2107 };
	bool sendPubKey(utils fileUtils, const SOCKET&, struct sockaddr_in*, unsigned char*, std::string username, char*) const;
	bool decryptAESKey(utils fileUtils, const char* uuid, const char* encryptedAESKey, unsigned char* AESKey) const;
	std::string retrievePrivateKey() const;
	unsigned char AESKey[AES_KEY_LEN] = {0};
	char uuid[CLIENT_ID_SIZE] = { 0 };

public:
	bool getClientServerInfo(utils fileUtil, char* uuid, char* filename, std::string&, uint16_t&) const;
	bool getServerPort(std::string& portNum, std::string& ip_address, uint16_t& port) const;
	bool registerUser(utils fileUtils, const SOCKET&, struct sockaddr_in*, std::string username, char*) const;
	bool sendFile(utils fileUtils, const SOCKET&, struct sockaddr_in*, char*, char*, std::string filename, char*, bool) const;
	bool handleSocketOperation(const SOCKET& sock, sockaddr_in* sa, const char* requestData, size_t requestDataSize, char* responseData, size_t responseBufferSize) const;
	bool loginUser(const SOCKET & sock, struct sockaddr_in* sa, char*, char*, char*) const;  
};