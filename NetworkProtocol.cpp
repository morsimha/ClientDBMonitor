#include "NetworkProtocol.h"

// Constructors and Destructors
ClientRequest::ClientRequest() {
    memset(_request.URequestHeader.buffer, 0, sizeof(_request.URequestHeader.SRequestHeader));
    _request.URequestHeader.SRequestHeader.version = SERVER_VER;
    _request.payload = nullptr;
}

ClientRequest::~ClientRequest() {
    delete[] _request.payload;
}

void ClientRequest::packRequest(char* buffer) {
    memcpy(buffer, _request.URequestHeader.buffer, sizeof(_request.URequestHeader));
    if (_request.payload != nullptr) {
        uint32_t payloadSize = _request.URequestHeader.SRequestHeader.payload_size;
        uint32_t currPayload = payloadSize < PACKET_SIZE - offset() ? payloadSize : PACKET_SIZE - offset();
        memcpy(buffer + sizeof(_request.URequestHeader), _request.payload, currPayload);
    }
}

uint32_t ClientRequest::offset() const {
    return sizeof(_request.URequestHeader);
}

//matching function for ClientResponse
ClientResponse::ClientResponse() {
    memset(_response.UResponseHeader.buffer, 0, sizeof(_response.UResponseHeader.SResponseHeader));
    _response.UResponseHeader.SResponseHeader.version = SERVER_VER;
    _response.payload = nullptr;
}

ClientResponse::~ClientResponse() {
    delete[] _response.payload;
}

void ClientResponse::unpackResponse(char* buffer) {
    memcpy(_response.UResponseHeader.buffer, buffer, sizeof(_response.UResponseHeader));
    char* ptr = buffer + sizeof(_response.UResponseHeader);
    uint32_t payload_size = _response.UResponseHeader.SResponseHeader.payload_size;
    if (payload_size > 0) {
        _response.payload = new char[payload_size];
        memcpy(_response.payload, ptr, payload_size);
    }
}

uint32_t ClientResponse::offset() const {
    return sizeof(_response.UResponseHeader);
}
