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

	char uuid[MAX_ID_SIZE] = { 0 };
	char username[MAX_USER_LEN] = { 0 };
	char filename[MAX_FILE_LEN] = { 0 };
	char AESEncrypted[ENC_AES_LEN] = { 0 };
	WSADATA wsaData;
	SOCKET sock;
	bool newUser;
	bool login_status = true, status = true;
	struct sockaddr_in sa = { 0 };
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData); 	

	// Failure in an of the functions inside the try/catch will lead to error printing and cleaning andterminating the run.
	try{
		// We check if any of the .info file exist, in order to initiate login or register.
		newUser = client.getClientServerInfo(fileUtils, username, filename, ip_addr, port);

		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		inet_pton(AF_INET, ip_addr.c_str(), &sa.sin_addr);

		if (!newUser) {
			sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			login_status = client.loginUser(sock, &sa, username, uuid, AESEncrypted);
		}
		// Trying to register if login failed or this is a new user.
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
		status = client.sendFile(fileUtils, sock, &sa, username, uuid, filename, AESEncrypted, newUser);
	}
		WSACleanup();

	if (status) {
		std::cout << "Run completed successfully!" << std::endl;
		return 0;
	}
	std::cerr << "-F- Run was not completed successfully." << std::endl;

	return 1;
}