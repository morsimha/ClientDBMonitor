# ClientDBMonitor

ClientDBMonitor is a C++ application that provides a secure client for file transmission over a TCP/IP network. The client ensures data integrity and security using AES and RSA encryption, with Base64 encoding for handling binary data. The program supports user registration, authentication, and secure file transfer to a server.

## Features

- **User Authentication:** Supports user login and registration. If a user does not exist or login fails, the client automatically attempts to register the user.
- **Secure File Transfer:** Encrypts files using AES encryption before sending them to the server, ensuring secure data transmission.
- **Base64 Encoding:** Encodes binary data using Base64 to ensure compatibility with text-based transmission protocols.
- **Error Handling:** Robust error handling using try-catch blocks to manage network or cryptographic failures.
- **Cross-Platform Network Communication:** Utilizes WinSock2 for handling TCP/IP communication on Windows.

## Dependencies

- **Windows OS:** The program is designed to run on Windows and depends on the WinSock2 library.
- **Cryptographic Libraries:** Includes RSA and AES wrappers for encryption, along with Base64 encoding utilities.
