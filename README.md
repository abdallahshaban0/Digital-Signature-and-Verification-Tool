# Digital-Signature-and-Verification-Tool

A graphical user interface (GUI) application for generating, signing, and verifying digital signatures using RSA and ECC (ECDSA) algorithms, as well as performing Elliptic Curve Diffie-Hellman (ECDH) key exchange. Built with PyQt5 and the `cryptography` library, this tool provides a secure and user-friendly way to ensure message integrity, authenticity, and secure key agreement.

## Features

- Generate 2048-bit RSA or SECP256K1 ECC key pairs for digital signatures.
- Sign messages or files using SHA-256 hashing with RSA (PSS padding) or ECC (ECDSA).
- Verify signatures to confirm authenticity and integrity.
- **(Bonus Task)** Perform ECDH key exchange to compute a shared secret using the SECP256K1 curve.
- Dark-themed interface for enhanced usability.
- Support for text messages and file inputs.
- Save/load keys in PEM format and signatures/shared secrets in base64 format.
- Copy keys to the clipboard for easy sharing or storage.

## Requirements

- Python 3.8 or higher
- Required packages:
  - `cryptography` (for cryptographic operations, including ECDH key exchange)
  - `PyQt5` (for the GUI)

## Installation

1. Clone the repository or download the source code:
   ```bash
   git clone https://github.com/abdallahshaban0/Digital-Signature-and-Verification-Tool.git
   cd Digital-Signature-and-Verification-Tool
