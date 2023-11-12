#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <iostream>
#include <string>
#include <iomanip>

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>
#include "Client.h"

#include <chrono>
#include <thread>

#pragma comment(lib, "ws2_32.lib")


int main() {
	Client client;
	utils fileUtils;
	std::string ip_addr;
	uint16_t port;

	if (!client.getServerInfo(fileUtils, ip_addr, port))
		return 1;
	char uuid[CLIENT_ID_SIZE] = { 0 };
	char username[USER_LENGTH] = { 0 };
	char AESEncrypted[ENC_AES_LEN] = { 0 };
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData); 	
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);	
	inet_pton(AF_INET, ip_addr.c_str(), &sa.sin_addr); 

	bool newUser;
	bool status = true;


	//std::remove(ME_INFO);

	// We check if any of the .info file exist, in order to initiate login or register.
	// if none exist, this is a failure

	try{
		newUser = client.getClientInfo(fileUtils, username);
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		status =  false;
	}

	if (status) {
		if (!newUser) {
			//TODO do I want to send empty pointer (last 3)?
			try {
				status = client.loginUser(sock, &sa, username, uuid, AESEncrypted);
			}
			catch (std::exception& e) {
				std::cerr << e.what() << std::endl;
				sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				newUser = true;
			}
		}

		if (newUser) {
			status = client.registerUser(fileUtils, sock, &sa, username, uuid);
		}
	}


	if (status) {
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		status = client.sendFile(fileUtils, sock, &sa, username, uuid, AESEncrypted, newUser);
	}
		WSACleanup();

	if (status)
		return 0;
	return 1;
}