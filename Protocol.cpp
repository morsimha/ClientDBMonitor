#include "Protocol.h"
// Protocol.h
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <cstring>

// Assuming SERVER_VER and other constants are defined somewhere
// Assuming structure definitions for headers are available

class Protocol {
protected:
    struct {
        union {
            char buffer[/* Size of the header */];
            SHeader SHeader;  // Assuming SHeader is the structure for header
        } UHeader;
        char* payload;
    } _entity;

public:
    Protocol() {
        std::memset(_entity.UHeader.buffer, 0, sizeof(_entity.UHeader.SHeader));
        _entity.UHeader.SHeader.version = SERVER_VER;
        _entity.payload = nullptr;
    }

    virtual ~Protocol() {
        delete[] _entity.payload;
    }

    uint32_t offset() const {
        return sizeof(_entity.UHeader);
    }

    // Other common methods can be added here
};

#endif // PROTOCOLENTITY_H


// Request.h
#ifndef REQUEST_H
#define REQUEST_H

#include "Protocol.h"

class Request : public Protocol {
public:
    void packRequest(char* buffer) {
        std::memcpy(buffer, _entity.UHeader.buffer, sizeof(_entity.UHeader));
        if (_entity.payload != nullptr) {
            uint32_t payloadSize = _entity.UHeader.SHeader.payload_size;
            uint32_t currPayload = payloadSize < PACKET_SIZE - offset() ? payloadSize : PACKET_SIZE - offset();
            std::memcpy(buffer + sizeof(_entity.UHeader), _entity.payload, currPayload);
        }
    }

    // Additional Request-specific methods
};

#endif // REQUEST_H


// Response.h
#ifndef RESPONSE_H
#define RESPONSE_H

#include "Protocol.h"

class Response : public Protocol {
public:
    void unpackResponse(char* buffer) {
        std::memcpy(_entity.UHeader.buffer, buffer, sizeof(_entity.UHeader));
        char* ptr = buffer + sizeof(_entity.UHeader);
        uint32_t payload_size = _entity.UHeader.SHeader.payload_size;
        if (payload_size > 0) {
            _entity.payload = new char[payload_size];
            std::memcpy(_entity.payload, ptr, payload_size);
        }
    }

    // Additional Response-specific methods
};

#endif // RESPONSE_H
