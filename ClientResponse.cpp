#include "ClientResponse.h"

/* Unpacks the buffer received into the ClientResponse struct according to the given protocol. */
void ClientResponse::unpackResponse(char* buffer)
{
	memcpy(_response.UResponseHeader.buffer, buffer, sizeof(_response.UResponseHeader));
	char* ptr = buffer + sizeof(_response.UResponseHeader);
	uint32_t payload_size = _response.UResponseHeader.SResponseHeader.payload_size;
	if (payload_size > 0) {
		_response.payload = new char[payload_size];
		memcpy(_response.payload, ptr, payload_size);
	}
}

/* Returns the header offset. */
uint32_t ClientResponse::offset() const
{
	return sizeof(_response.UResponseHeader);
}

/* ctor */
ClientResponse::ClientResponse()
{
	memset(_response.UResponseHeader.buffer, 0, sizeof(_response.UResponseHeader.SResponseHeader));
	_response.UResponseHeader.SResponseHeader.version = SERVER_VER;
	_response.payload = nullptr;
}

/* dtor */
ClientResponse::~ClientResponse()
{
	delete[] _response.payload;
}
