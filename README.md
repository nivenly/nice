# DID Manager

![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)
![Go Version](https://img.shields.io/badge/Go-1.19-blue)
![PostgreSQL Version](https://img.shields.io/badge/PostgreSQL-14+-blue)
![Build Status](https://img.shields.io/badge/build-passing-green)

The **DID Manager** is a modern Decentralized Identifier (DID) management system built with **Golang** and **PostgreSQL**. It supports the creation, signing, and management of DIDs and their attributes using Ed25519 cryptography. The project complies with W3C DID standards, providing a robust API and intuitive web interface.

## Features

- **Generate Decentralized Identifiers (DIDs)** with deterministic UUIDv5.
- **Sign and Verify Attributes** securely using Ed25519 keys.
- **List DIDs and Attributes** with all signatures.
- **Secure Storage** of private keys and DIDs in PostgreSQL.
- Fully responsive **Web Frontend** with TailwindCSS.
- **API Endpoints** for programmatic access to DID operations.
- HTTPS support with **Let’s Encrypt TLS certificates**.

---

## Technologies Used

- **Programming Language**: Golang
- **Database**: PostgreSQL
- **Frontend**: HTML, JavaScript, TailwindCSS
- **Cryptography**: Ed25519, UUIDv5
- **Web Framework**: Gin
- **TLS**: Let’s Encrypt

---

## Installation

Follow these steps to install and configure the DID Manager on your system.

### Prerequisites

- Golang 1.19+
- PostgreSQL 14+
- A valid domain name for HTTPS setup
- Let’s Encrypt installed for SSL certificates
- `pgcrypto` PostgreSQL extension for UUID generation
