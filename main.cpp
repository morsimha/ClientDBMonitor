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
	SOCKET sock;

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);	
	inet_pton(AF_INET, ip_addr.c_str(), &sa.sin_addr); 

	bool newUser;
	bool login_status = true, status = true;


	//std::remove(ME_INFO);

	// failure in an of the functions inside the try/catch will lead to error printing and cleaning andterminating the run.
	try{
		// We check if any of the .info file exist, in order to initiate login or register.
		newUser = client.getClientInfo(fileUtils, username);

		if (!newUser) {
			//TODO do I want to send empty pointer (last 3)?
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			login_status = client.loginUser(sock, &sa, username, uuid, AESEncrypted);
		}
		// trying to register if login failed or this is a new user.
		if (!login_status or newUser) {
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			status = client.registerUser(fileUtils, sock, &sa, username, uuid);
			newUser = true;
		}
	}

	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		status =  false;
	}


	if (status) {
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		login_status = client.sendFile(fileUtils, sock, &sa, username, uuid, AESEncrypted, newUser);
	}
		WSACleanup();

	if (status)
		return 0;
	return 1;
}