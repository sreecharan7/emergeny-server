# Emergency Server

A decentralized emergency contact system with blockchain-like features for trustless verification of emergency services contact information.

## Overview

This project implements a distributed protocol for emergency services discovery and verification:

- **Emergency Server**: Authoritative source for emergency contact numbers (police, ambulance, etc.)
- **Emergency Client**: Discovers servers and peer clients, verifies contact information cryptographically
- **Peer-to-Peer Exchange**: Clients can share verified information with other clients

The system uses UDP broadcasting for discovery and TCP for data transfer. All information is cryptographically signed using RSA, ensuring authenticity regardless of source.

## Key Features

- **Decentralized Architecture**: Information can flow from server-to-client or client-to-client
- **Cryptographic Verification**: All data is signed using RSA signatures, making it verifiable regardless of source
- **Trustless Protocol**: Clients verify information authenticity without trusting the information provider
- **Local Caching with Time-Based Expiry**: Verified information is temporarily stored in an expiring map
- **Distributed Redundancy**: Multiple clients can serve as information providers

## Blockchain-like Characteristics

- **Cryptographic Signatures**: Similar to blockchain transactions, all information is cryptographically signed
- **Distributed Ledger Concept**: Contact information can be verified and distributed across peers
- **Decentralized Trust**: No need to trust individual nodes, only the cryptographic verification
- **Network Resilience**: System can function even if the main server is unavailable, using peer information

## Components

### 1. Emergency Client (`emergencyClient.cpp`)
- Broadcasts discovery requests on the network
- Verifies responses using RSA signature validation
- Maintains a time-expiring cache of verified information
- Can function as a server for other clients using cached information

### 2. Emergency Server (`emergencyServer.cpp`)
- Primary source for emergency contact information
- Signs all responses with its private key
- Manages multiple worker threads for handling concurrent requests

## Prerequisites

- C++ compiler with C++11 support
- OpenSSL development libraries
- POSIX-compliant operating system (Linux, macOS)

## Building the Project

1. Compile the server:
```bash
g++ -o emergencyServer emergencyServer.cpp -std=c++11 -pthread -lssl -lcrypto
```

2. Compile the client:
```bash
g++ -o emergencyClient emergencyClient.cpp -std=c++11 -pthread -lssl -lcrypto
```

## Running the System

### Starting the Server

```bash
./emergencyServer
```

The server will start listening on port 25642 for discovery broadcasts.

### Using the Client

```bash
./emergencyClient
```

The client will display a menu of available emergency services:

1. Police station number
2. Ambulance Number
3. Fire Station Number
4. Vehicle repair Number
5. Food delivery
6. Blood bank Number

Enter the number corresponding to the service you need, and the client will:
1. Broadcast a discovery request on the network
2. Receive and verify responses (either from a server or other clients)
3. Store verified information for future use and sharing with other clients
4. Display the authenticated contact information

Enter `999` to quit the application.

## Security Protocol

The system implements a signature-based verification protocol:

1. All information originates from the server and is signed with the server's private key
2. Clients verify the signature using the server's public key
3. Verified information is cached by clients and can be shared with other clients
4. Other clients can verify the signature regardless of whether they received it from the server or another client
5. The `ExpiringMap` class implements time-based expiration of cached information

### Key Files
- `public_key.pem`: Used by clients to verify message signatures
- `private_key.pem`: Used by the server to sign messages (must be kept secure)

## Network Protocol Flow

### Initial Discovery
1. Client broadcasts a query: `"The global emergency contact Id:-X, TID:-Y"`
2. Server (or informed client) receives the broadcast
3. Responder returns a signed message with contact information
4. Client verifies signature and caches the result

### Client-to-Client Sharing
1. Client A receives and verifies information from the server
2. Client A stores verified information in its expiring map
3. When Client B broadcasts a discovery request, Client A can respond with its cached information
4. Client B verifies the signature (which is still the server's original signature)
5. The information is trusted because the signature is valid, not because Client A is trusted

### Notes

- when you are running the server and client on same machine , run server first
