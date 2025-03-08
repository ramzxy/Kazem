# KazemVPN Client

An educational VPN client implementation in C++ to understand the fundamentals of VPN technology.

## Overview

This project demonstrates the core components of a VPN client:

1. **Connection Management**: Establishing and maintaining a secure connection to a VPN server
2. **Encryption**: Securing data with strong encryption (AES-256)
3. **Tunneling**: Creating a virtual network interface and routing traffic through it

The code is heavily commented to explain each step of the VPN process, making it an excellent learning resource.

## Components

The project is structured into several key components:

- **Connection**: Handles the network connection to the VPN server
- **Encryption**: Manages encryption and decryption of VPN traffic
- **Tunnel**: Creates and manages the virtual network interface and packet routing
- **Main**: Ties everything together and provides the user interface

## Requirements

- C++17 compatible compiler
- Boost libraries (system, thread)
- OpenSSL
- CMake 3.10 or higher
- Linux or macOS (Windows support would require additional code)

## Building

```bash
# Create a build directory
mkdir -p build
cd build

# Generate build files
cmake ..

# Build the project
make
```

## Running

```bash
# Basic usage with default settings (connects to 127.0.0.1:8090)
./bin/KazemVPN

# Connect to a specific server
./bin/KazemVPN 192.168.1.100 8080
```

Press Ctrl+C to disconnect and exit.

## Educational Notes

This implementation is primarily for educational purposes and includes:

- Detailed comments explaining VPN concepts
- Simplified implementations of complex components
- Debug output to understand the flow of data

For a production VPN client, you would need to add:

1. More robust error handling
2. Better authentication mechanisms
3. Support for VPN protocols like OpenVPN or WireGuard
4. Cross-platform support
5. Performance optimizations
6. User interface

## VPN Server

This client requires a compatible VPN server to connect to. The server should:

1. Accept TCP connections on the specified port
2. Respond to the handshake protocol
3. Handle encrypted packets
4. Route traffic to the internet

A simple test server is not included in this project.

## License

This project is provided for educational purposes only.

## Disclaimer

This code is not intended for production use. It lacks many security features required for a real VPN client. Do not use it to protect sensitive communications. 