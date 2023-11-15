/*
NetworkProtocol.h
*/

#pragma once
#include <iostream>
#include <stdint.h>

#define CLIENT_SIZE 16
#define PACKET_SIZE 1024
#define SERVER_VER 3

class ClientRequest {
	friend class Client;
#pragma pack(push, 1)
	struct RequestFormat {
		union URequestHeader {
			struct SRequestHeader {
				char cliend_id[CLIENT_SIZE];
				uint8_t version;
				uint16_t code;
				uint32_t payload_size;
			} SRequestHeader;
			char buffer[sizeof(SRequestHeader)];
		} URequestHeader;
		char* payload;
	} _request;
#pragma pack(pop)
	void packRequest(char*);
	uint32_t offset() const;
	ClientRequest();
	~ClientRequest();
};

class ClientResponse {
	friend class Client;
#pragma pack(push, 1)
	struct ResponseFormat {
		union UResponseHeader {
			struct SResponseHeader {
				uint8_t version;
				uint16_t code;
				uint32_t payload_size;
			} SResponseHeader;
			char buffer[sizeof(SResponseHeader)];
		} UResponseHeader;
		char* payload;
	} _response;
#pragma pack(pop)
	void unpackResponse(char*);
	uint32_t offset() const;
	ClientResponse();
	~ClientResponse();
};