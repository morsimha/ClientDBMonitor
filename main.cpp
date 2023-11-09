#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <iostream>
#include <string>
#include <iomanip>

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>
#include "Action.h"

#include <chrono>
#include <thread>

#pragma comment(lib, "ws2_32.lib")


int main() {
	Action handler;
	std::string ip_addr;
	uint16_t port;
	if (!handler.getServerInfo(ip_addr, port))
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

	bool is_new_user = true;
	bool status;

	//handler.registerUser(sock, &sa, uuid);
	try {
		status = handler.registerUser(sock, &sa, uuid);
	}
	catch (std::exception& e) {
		// maybe remove
		std::cerr << "Exception caught: " << e.what() << std::endl;
		is_new_user = false;
		status = handler.loginUser(sock, &sa, username, uuid, AESEncrypted);
	}

	if (status) {
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		status = handler.sendFile(sock, &sa, uuid, AESEncrypted, is_new_user);
	}
		WSACleanup();

	if (status)
		return 0;
	return 1;
}