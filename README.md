# Digital-Signature-and-Verification-Tool

A graphical user interface (GUI) application for generating, signing, and verifying digital signatures using RSA and ECC algorithms. Built with PyQt5 and the `cryptography` library, this tool provides a secure and user-friendly way to ensure message integrity and authenticity.

## Features

- Generate 2048-bit RSA or SECP256K1 ECC key pairs.
- Sign messages or files using SHA-256 hashing with RSA (PSS padding) or ECC (ECDSA).
- Verify signatures to confirm authenticity and integrity.
- Dark-themed interface for enhanced usability.
- Support for text messages and file inputs.
- Save/load keys in PEM format and signatures in base64 format.
- Copy keys to the clipboard for easy sharing or storage.

## Requirements

- Python 3.8 or higher
- Required packages:
  - `cryptography` (for cryptographic operations)
  - `PyQt5` (for the GUI)

## Installation

1. Clone the repository or download the source code:
   ```bash
   git clone https://github.com/abdallahshaban0/Digital-Signature-and-Verification-Tool.git
   cd Digital-Signature-and-Verification-Tool
   ```

2. Install the required packages:
   ```bash
   pip install cryptography PyQt5
   ```

   If a `requirements.txt` file is included:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Using the Application:
   - **Key Generation Tab**:
     - Select RSA or ECC from the dropdown menu.
     - Click "Generate New Keys" to create a key pair.
     - View keys in PEM format in the display area.
     - Save keys to PEM files with "Save Keys" or copy them with "Copy Keys."
     - Load existing keys using "Load Keys" and selecting PEM files.
   - **Sign/Verify Tab**:
     - Enter a message or click "Select File" to load file contents.
     - Click "Sign" to generate a base64-encoded signature using the private key.
     - View the signature in the display area.
     - To verify, paste or load a base64-encoded signature with "Load Signature," then click "Verify" using the public key.
     - Save signatures to a text file with "Save Signature."

## Security Features

- **Message Hashing**: Employs SHA-256 for secure message hashing.
- **RSA Implementation**: Uses 2048-bit keys with PSS padding for enhanced security.
- **ECC Implementation**: Utilizes the SECP256K1 curve, widely used in cryptographic standards.
- **Secure Key Handling**: Keys are generated securely and stored in memory during runtime.
- **Error Handling**: Ensures valid keys and signatures are used, with user-friendly error messages.

## Notes

- **Key Security**: Private keys are sensitive; store them securely and avoid sharing.
- **Key Storage**: Keys are not saved to disk automatically; use "Save Keys" to persist them.
- **File Support**: Files are decoded as UTF-8 with error handling for compatibility.
- **Production Use**: Implement secure key management practices for production environments.

## License

This project is licensed under the MIT License.