# crypt2chat

**crypt2chat** is a secure Python-based instant messaging application, designed with end-to-end encryption to prioritize user privacy. Built on a robust cryptographic foundation, crypt2chat uses secure protocols to ensure message confidentiality, integrity, and authentication. The application is **currently under development** and is not yet finished, but users can contribute and request features or report issues.

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Security Protocols](#security-protocols)
- [Architecture](#architecture)
  - [Client](#client)
  - [Server](#server)
- [Future Improvements](#future-improvements)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

**crypt2chat** is an end-to-end encrypted messaging app that ensures secure communication between users by preventing message interception, impersonation, and unauthorized message alteration. It operates through a server-client model, where the server acts only as a message relay without accessing the content of the messages. The cryptographic operations required for encryption and decryption are performed locally on each client.

> **Note**: The application is still under development. It may be subject to changes and improvements.

## Features

- **End-to-End Encryption**: Protects all messages so that only the intended recipients can read them.
- **Message Integrity**: Verifies that messages have not been tampered with.
- **Authentication Protection**: Prevents the server from impersonating clients.
- **Group Conversations**: Supports secure group messaging.
- **Containerized Server**: The server is containerized with Docker for easy deployment and scalability.
- **Database Flexibility**: Currently uses SQLite3 with plans to migrate to PostgreSQL for enhanced scalability.

## Security Protocols

crypt2chat utilizes advanced cryptographic protocols to protect messages:

- **X3DH Protocol**: Used for secure key exchange, enabling both parties to establish a shared secret even on first contact.
- **AES-GCM Encryption**: Ensures message confidentiality and integrity with AES encryption in Galois/Counter Mode.
- **RSA, X448, and ED448 Keys**: Provides strong encryption and digital signatures for secure communication.
  
These protocols ensure that the server has no access to the actual message content or user credentials, and cannot alter or impersonate messages.

## Architecture

crypt2chat is built on a modular client-server architecture, optimizing for security and scalability.

### Client

- **Built with PyQt6**: A robust graphical interface, ensuring smooth user interaction across platforms.
- **Local Encryption**: All cryptographic operations for encryption and decryption of messages occur locally on the client.
- **Multi-User & Group Support**: Allows users to engage in one-on-one or group conversations securely.

### Server

- **Framework**: Developed using FastAPI, with Uvicorn as the ASGI server.
- **Database**: Uses SQLite3 for development, with planned migration to PostgreSQL for improved concurrency and data integrity.
- **Containerization**: Docker is used to package and deploy the server environment, simplifying installation and scaling on cloud or on-premises environments.

The server only serves as a message relay and storage hub, holding encrypted messages without any capability to decrypt or alter them.

## Setup and Installation

### Requirements

To run **crypt2chat**, all the necessary dependencies are listed in the `requirements.txt` file. Please consult this file for the complete list of Python packages required to run both the client and the server.

## Future Improvements

- **PostgreSQL Migration**: Transitioning from SQLite3 to PostgreSQL for improved scalability and reliability.

## Contributing

We welcome contributions to enhance **crypt2chat**. If you have any suggestions, feature requests, or bug reports, please open an **issue** in the repository.

### How to contribute:
- **Submit Issues**: Report bugs, request features, or ask for help.
- **Submit Pull Requests**: Fork the repository, implement your changes, and create a pull request for review.

## License

This project is licensed under the GNU Public License. See the `LICENSE` file for more details.