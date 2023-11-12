#include "Client.h"
// TODO Consider class or any way that doesnt require utils init every time.

/* Places the server info into the received variables. Returns true upon success and false upon failure. */

bool Client::getClientInfo(utils fileUtils, char* username) const {
	std::fstream file;
	std::string name;


	// Check if 'me.info' exists and open it
	if (fileUtils.isFile(ME_INFO)) {
		std::cout << "me.info file found, accessing login information.." << std::endl;
		if (!fileUtils.openFile(ME_INFO, file, false))
			throw std::runtime_error("Error: cannot open Me.info file.");

		std::getline(file, name);
		memcpy(username, name.c_str(), USER_LENGTH);
		fileUtils.closeFile(file);
		// not a new user - returing false

		return false;
	}
	else if (fileUtils.isFile(TRANSFER_INFO)) {
		std::cout << "only transfer.info file found, accessing register information.." << std::endl;
		if (!fileUtils.openFile(TRANSFER_INFO, file, false))
			throw std::runtime_error("Error: cannot open Me.info file.");
		std::getline(file, name);
		std::getline(file, name);
		memcpy(username, name.c_str(), USER_LENGTH);
		fileUtils.closeFile(file);
		// new user - returing true
		return true;
	}

	//std::cerr << "Error: Transfer.info and Me.info files do not exist. " << std::endl;
	throw std::runtime_error("Error: Transfer.info and Me.info files do not exist.");

}

bool Client::getServerInfo(utils fileUtils, std::string& ip_address, uint16_t& port) const
{
	std::fstream newFile;
	std::string fullLine;
	if (!fileUtils.isFile(TRANSFER_INFO)) {
		std::cerr << "Error: Transfer file doesn't exist. " << std::endl;
		return false;
	}
	if (!fileUtils.openFile(TRANSFER_INFO, newFile, false))
		return false;
	
	if (!std::getline(newFile, fullLine)) {
		std::cerr << "Error reading from transfer file. " << std::endl;
		return false;
	}
	fileUtils.closeFile(newFile);

	size_t pos = fullLine.find(":");
	ip_address = fullLine.substr(0, pos);
	fullLine.erase(0, pos + 1);

	int tmp = std::stoi(fullLine);
	if (tmp <= static_cast<int>(UINT16_MAX) && tmp >= 0)
		port = static_cast<uint16_t>(tmp);
	else {
		std::cerr << "Error: Port is invalid." << std::endl;
		return false;
	}
	return true;
}

bool Client::loginUser(const SOCKET& sock, struct sockaddr_in* sa, char* username, char* uuid, char* AESKey) const {

	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };

	// Set the request header fields for a login request
	req._request.URequestHeader.SRequestHeader.payload_size = strlen(username) + 1;  // +1 for the null terminator
	req._request.payload = new char[strlen(username) + 1];  // +1 for the null terminator
	memcpy(req._request.payload, username, strlen(username) + 1);  // +1 to include the null terminator
	req._request.URequestHeader.SRequestHeader.code = LOGIN_REQUEST;

	// Pack the request and send it
	req.packRequest(requestBuffer);
	send(sock, requestBuffer, PACKET_SIZE, 0);

	// Receive the server response
	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);

	// Check for a successful login response code
	if (res._response.UResponseHeader.SResponseHeader.code == LOGIN_SUCCESS) {
		std::cout << "Successfully logged in - " << username << std::endl;
		// Copy the encrypted AES key and the UUID from the response payload
		memcpy(uuid, res._response.payload, CLIENT_ID_SIZE);
		memcpy(AESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		return true;
	}

	else if (res._response.UResponseHeader.SResponseHeader.code == LOGIN_ERROR) {
		std::cerr << "Error: Failed to login, this user needs to be registered!" << std::endl;
		std::cerr << "Trying to login instead.." << std::endl;
		closesocket(sock);
	}

	else if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Server failed to login the user for unkown reason. " << std::endl;
	}
	return false;

}

/* Deals with user registration to the server. */
bool Client::registerUser(utils fileUtils, const SOCKET& sock, struct sockaddr_in* sa, std::string username, char* uuid) const
{
	std::fstream newFile;
	//std::string uuid_from_ME;
	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };

	if (username.length() >= USER_LENGTH) {
		std::cout << "Username doesn't meet the length criteria. " << std::endl;
		return false;
	}

	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa)); /* Connection to the server */
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + 1;
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.payload, username.c_str(), username.length() + 1);
	req._request.URequestHeader.SRequestHeader.code = REGISTER_REQUEST;

	req.packRequest(requestBuffer);
	std::cout << "Sending register request for " << username << "." << std::endl;
	send(sock, requestBuffer, PACKET_SIZE, 0);
	
	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);

	// Creating me.info file for a new user.
	if (res._response.UResponseHeader.SResponseHeader.code == REGISTER_SUCCESS) {

		bool retFlag;
		bool retVal = addUserToMeFile(fileUtils, newFile, username, res, uuid, retFlag);
		if (retFlag) return retVal;

		closesocket(sock);
		return true;

	}
	else if(res._response.UResponseHeader.SResponseHeader.code == REGISTER_ERROR) {
		std::cout << "Error: Failed to register user, the user is already registered, try to login instead. " << std::endl;
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Failed to register user due to a general error. " << std::endl;
	}
	return false;
}

/* Sends the RSA Public Key and inserts the received AES key into AESKey. */
bool Client::sendPubKey(utils fileUtils, const SOCKET& sock, sockaddr_in* sa, unsigned char* AESKey, std::string username, char* uuid) const
{
	RSAPrivateWrapper rsapriv;
	std::string pubkey = rsapriv.getPublicKey();
	RSAPublicWrapper rsapub(pubkey);
	std::fstream newFile;
	std::fstream privFile;

	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	std::string privkey = rsapriv.getPrivateKey();
	std::string encoded_privkey = Base64Wrapper::encode(privkey);

	bool retFlag;
	bool retVal = addPrivkeyToMeFile(fileUtils, newFile, encoded_privkey, retFlag);
	if (retFlag) return retVal;

	// Open or create the file "priv.key" for writing
	if (!fileUtils.openFileOverwrites(PRIV_KEY, privFile))
		return false;

	// Write the private key to "priv.key"
	fileUtils.writeToFile(privFile, encoded_privkey.c_str(), encoded_privkey.length());

	// Close the file "priv.key"
	fileUtils.closeFile(privFile);

	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };
	if (username.length() >= USER_LENGTH) {
		std::cout << "Username doesn't meet the length criteria. " << std::endl;
		return false;
	}

	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + 1 + PUB_KEY_LEN;
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	memcpy(req._request.payload, username.c_str(), username.length() + 1);
	memcpy(req._request.payload + username.length() + 1, pubkey.c_str(), PUB_KEY_LEN);
	std::cout << "Sending the following pubkey: " << pubkey.c_str() << "." << std::endl;
	req._request.URequestHeader.SRequestHeader.code = PUB_KEY_SEND;

	req.packRequest(requestBuffer);
	send(sock, requestBuffer, PACKET_SIZE, 0);

	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);
	if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Server failed to receive Public Key. " << std::endl;
		return false;
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == PUB_KEY_RECEVIED) {
		RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());
		char encryptedAESKey[ENC_AES_LEN] = { 0 };

		memcpy(encryptedAESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		std::string decryptedAESKey = rsapriv_other.decrypt(encryptedAESKey, ENC_AES_LEN);
		memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);

		return true;
	}
	return false;
}

bool Client::addUserToMeFile(utils& fileUtils, std::fstream& newFile, std::string& username, Response& res, char* uuid, bool& retFlag) const
{
	retFlag = true;
	if (!fileUtils.openFileOverwrites(ME_INFO, newFile))
		return false;

	fileUtils.writeToFile(newFile, username.c_str(), username.length());
	fileUtils.writeToFile(newFile, "\n", strlen("\n"));
	fileUtils.hexifyToFile(newFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
	fileUtils.closeFile(newFile);

	std::cout << "Updated ME INFO file with name and UUID." << std::endl;
	memcpy(uuid, res._response.payload, CLIENT_ID_SIZE);
	retFlag = false;
	return {};
}

bool Client::addPrivkeyToMeFile(utils& fileUtils, std::fstream& newFile, std::string& encoded_privkey, bool& retFlag) const
{
	retFlag = true;
	if (!fileUtils.openFile(ME_INFO, newFile, true))
		return false;

	fileUtils.writeToFile(newFile, "\n", strlen("\n"));
	fileUtils.writeToFile(newFile, encoded_privkey.c_str(), encoded_privkey.length());
	fileUtils.closeFile(newFile);
	retFlag = false;
	return {};
}

bool Client::decryptAESKey(utils fileUtils, const char* uuid, const char* encryptedAESKey, unsigned char* AESKey) const
{
	RSAPrivateWrapper rsapriv2;
	std::fstream privFile;

	// Open the priv.key file
	if (!fileUtils.openFile(PRIV_KEY, privFile, false)) {
		std::cerr << "Error: Failed to open priv.key file." << std::endl;
		return false;
	}

	// Read the encoded private key from priv.key
	std::string encoded_privkey= "";
	std::string temp_privkey_line = "";
	for (int i = 0; i < PRIV_KEY_LINES; i++) {
		std::getline(privFile, temp_privkey_line);
		encoded_privkey += temp_privkey_line;
	}
	fileUtils.closeFile(privFile);

	// Assume Base64Wrapper::decode is the method to decode base64 encoded strings
	std::string privkey = Base64Wrapper::decode(encoded_privkey);
	
	// Create RSAPrivateWrapper object with the private key
	RSAPrivateWrapper rsapriv(privkey);

	try {
		// Decrypt the encrypted AES key using the private key
		std::string decryptedAESKey = rsapriv.decrypt(encryptedAESKey, ENC_AES_LEN);
		// Copy the decrypted AES key to AESKey buffer
		memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);
	}
	catch (const std::exception& e) {
		// Catch and handle the exception
		std::cerr << "Failed generating AESKey, Please check if your priv.key matches the username and key stored in me.info.  " << std::endl;
		return false;
	}

	return true;
}

/* The function handles sending a file over to the server. */
bool Client::sendFile(utils fileUtils, const SOCKET& sock, sockaddr_in* sa, char* username, char* uuid, char* EncryptedAESKey,bool isNewUser) const
{
	unsigned char AESKey[AES_KEY_LEN] = { 0 };
	std::fstream requestedFile;
	char requestBuffer[PACKET_SIZE] = { 0 };


	if (isNewUser){
		if (!sendPubKey(fileUtils, sock, sa, AESKey, username, uuid))
			return false;
			}
	else {
		if (!decryptAESKey(fileUtils, uuid, EncryptedAESKey, AESKey))
			return false;
		try {
			int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa)); /* Connection to the server */
		}
		catch (std::exception& e) {
			std::cerr << "Exception: " << e.what() << std::endl;
			return false;
		}
	}
	
	if (!fileUtils.isFile(TRANSFER_INFO)) {
		std::cerr << "Error: Transfer file doesn't exist. Cannot retrieve file name. " << std::endl;
		closesocket(sock);
		return false;
	}
	if (!fileUtils.openFile(TRANSFER_INFO, requestedFile, false)) {
		std::cerr << "Error: Failed to open TRANSFER INFO file." << std::endl;
		closesocket(sock);
		return false;
	}
	
	std::string filename;

	for (int i = 0; i < TRANSFER_LINES; i++)
		std::getline(requestedFile, filename);
	
	fileUtils.closeFile(requestedFile);
	
	if (filename.length() > MAX_CHAR_FILE_LEN) {
		std::cerr << "Error: Filename length too long. " << std::endl;
		closesocket(sock);
		return false;
	}

	if (!fileUtils.isFile(filename)) {
		std::cerr << "Error: Filename doesn't exist. " << std::endl;
		closesocket(sock);
		return false;
	}

	std::cout << "Filename successfully found in transer_info. Preparing to send file." << std::endl;

	Request req;
	uint32_t fileSize = fileUtils.getFileSize(filename);
	uint32_t contentSize = fileSize + (AES_BLOCK_SIZE - fileSize % AES_BLOCK_SIZE); // After encryption
	req._request.URequestHeader.SRequestHeader.payload_size = contentSize + MAX_CHAR_FILE_LEN + sizeof(uint32_t);
	uint32_t payloadSize = req._request.URequestHeader.SRequestHeader.payload_size;
	req._request.payload = new char[payloadSize];
	memset(req._request.payload, 0, payloadSize);
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	req._request.URequestHeader.SRequestHeader.code = FILE_SEND;

	uint32_t currPayload = payloadSize < PACKET_SIZE - req.offset() ? payloadSize : PACKET_SIZE - req.offset();

	char* payloadPtr = req._request.payload;
	memcpy(payloadPtr, &contentSize, sizeof(uint32_t));
	payloadPtr += sizeof(uint32_t);
	memcpy(payloadPtr, filename.c_str(), filename.length());
	payloadPtr += MAX_CHAR_FILE_LEN;
	
	// Read File into Payload
	std::string filepath = "./" + filename; // We assume the file is in current dir
	fileUtils.openFileBin(filepath, requestedFile, false);
	fileUtils.readFileIntoPayload(requestedFile, payloadPtr, fileSize);
	fileUtils.closeFile(requestedFile);


	// Calculate checksum of file before encryption
	CRC digest;
	digest.update((unsigned char*)payloadPtr, fileSize);
	uint32_t checksum = digest.digest();

	AESWrapper wrapper(AESKey, AES_KEY_LEN);
	std::string tmpEncryptedData = wrapper.encrypt(payloadPtr, fileSize);
	memcpy(payloadPtr, tmpEncryptedData.c_str(), tmpEncryptedData.length());	
	
	bool crc_confirmed = false;
	size_t tries = 0;

	while (tries < MAX_TRIES && !crc_confirmed) {
		req.packRequest(requestBuffer);
		send(sock, requestBuffer, PACKET_SIZE, 0); // 1028

		uint32_t sizeLeft = payloadSize - currPayload;
		payloadPtr = req._request.payload + currPayload;
		while (sizeLeft > 0) {
			memset(requestBuffer, 0, PACKET_SIZE);
			currPayload = sizeLeft < PACKET_SIZE ? sizeLeft : PACKET_SIZE;
			memcpy(requestBuffer, payloadPtr, currPayload);
			send(sock, requestBuffer, PACKET_SIZE, 0);

			sizeLeft -= currPayload;
			payloadPtr += currPayload;
		} // Finish sending file

		char buffer[PACKET_SIZE] = { 0 };
		recv(sock, buffer, PACKET_SIZE, 0); // Expecting Code 2103

		Response res;
		res.unpackResponse(buffer);
		if (res._response.UResponseHeader.SResponseHeader.code != FILE_OK_CRC) {
			std::cout << "Error: Server responded with an error. " << std::endl;
			closesocket(sock);
			return false;
		}

		std::cout << "Server received file, checking checksum.." << std::endl;

		uint32_t received_checksum;
		memcpy(&received_checksum, res._response.payload + sizeof(uint32_t) + MAX_CHAR_FILE_LEN, sizeof(uint32_t));

		if (checksum == received_checksum) {
			crc_confirmed = true;
			std::cout << "Checksum matches!" << std::endl;
		}
		else {
			tries++;
			std::cout << "Checksum does not match: " << tries << "/3" << " tries." << std::endl;
		}

		Request newReq;
		newReq._request.URequestHeader.SRequestHeader.code = crc_confirmed ? CRC_OK : CRC_INVALID_RETRY;
		if (tries == MAX_TRIES)
			newReq._request.URequestHeader.SRequestHeader.code = CRC_INVALID_EXIT;

		newReq._request.URequestHeader.SRequestHeader.payload_size = MAX_CHAR_FILE_LEN;
		newReq._request.payload = new char[MAX_CHAR_FILE_LEN];
		memcpy(newReq._request.payload, filename.c_str(), filename.length());
		memcpy(newReq._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
		memset(requestBuffer, 0, PACKET_SIZE);
		newReq.packRequest(requestBuffer);
		send(sock, requestBuffer, PACKET_SIZE, 0);
	}

	try {
		char buffer[PACKET_SIZE] = { 0 };
		recv(sock, buffer, PACKET_SIZE, 0); // Expecting Code 2104

		Response res;
		res.unpackResponse(buffer);
		if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
			std::cout << "Error: Server did not confirm receiving the message. " << std::endl;
			closesocket(sock);
			return false;
		}
		else if(res._response.UResponseHeader.SResponseHeader.code == MSG_RECEIVED){
			std::cout << "The file was successfully (and safely) uploaded to the server." << std::endl;
		}
	}
	catch (std::exception& e) {
		std::cerr << "Couldn't receive final answer. Exception: " << e.what() << std::endl;
		closesocket(sock);
		return false;
	}

	closesocket(sock);
	return true;
}



