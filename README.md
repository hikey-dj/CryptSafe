# CryptSafe

CryptSafe is a versatile C++ library designed to provide robust cryptographic functionalities. It allows users to validate digital signatures using SHA-256, RSA, and AES for secure encryption and decryption operations. Additionally, CryptSafe includes a command-line tool that enables users to interact with these cryptographic features through specific prompts. A static Python API is also available, providing Python developers with a convenient interface to upload files securely.

## Technical Implementation

CryptSafe leverages the Crypto++ library in C++ for implementing SHA-256, RSA, and AES cryptographic algorithms. The library ensures robust security through these advanced encryption standards. Furthermore, the Python `ctypes` library is utilized to create a static Python API, enhancing accessibility and usability across different programming environments.

## Functions in Library

### RSA Key Pair Generation

- **Function:** `generateRSAKeyPair(const string& privateKeyFile, const string& publicKeyFile)`
- **Description:** Generates RSA private and public key pairs of 2048 bits using Crypto++ library's random number generator. Saves the keys to specified files for subsequent cryptographic operations.
- **Usage:** Users provide paths for storing the generated private and public keys.

### Digital Signatures (Using SHA-256 and RSA)

- **Functions Involved:**
  - `signHash(const string &hash, RSA::PrivateKey &privateKey)`
  - `verifySHA256(const string &hash, const string &signature, const RSA::PublicKey &publicKey)`
- **Description:**
  - **Signing:** Computes the SHA-256 hash of data and signs it using the sender's private RSA key, producing a digital signature.
  - **Verification:** Verifies the authenticity of received data by using the sender's public RSA key to decrypt the signature and comparing it with the computed hash.
- **Usage:** Ensures data integrity and authenticity in digital communications.

### AES Encryption and Decryption with RSA Key Exchange

- **Functions Involved:**
  - `encryptFile(const string &fileName, const string &encryptFileName, const string &publicKeyFile, const string &privateKeyFile)`
  - `decryptFile(const string &fileName, const string &decryptFileName, const string &publicKeyFile, const string &privateKeyFile)`
- **Description:**
  - **Encryption:** Encrypts a file using AES algorithm with a randomly generated key. Encrypts the AES key using the recipient's public RSA key for secure transmission.
  - **Decryption:** Decrypts an AES-encrypted file using the recipient's private RSA key to obtain the AES key, then decrypts the file content. Verifies the digital signature to ensure data integrity before saving the decrypted content.
- **Usage:** Provides secure file encryption and decryption with robust RSA-based key exchange.

These functions collectively enable CryptSafe to offer secure handling of encryption, decryption, and digital signatures using RSA and AES algorithms, ensuring confidentiality, integrity, and authenticity of digital data.

## Usage

### Library Compilation Instructions

To compile a file using our library, please follow these steps:

1. After extracting the zip file, you will find a `cryptsafe` folder within the main `CryptSafe` folder.
2. Place your source file (e.g., `main.cpp`) in the same directory as the `cryptsafe` folder.
3. To compile your file with `g++`, use the following command:
######
    g++ -o main main.cpp -I./cryptsafe -L./cryptsafe -lcryptsafe -lcryptopp
   This command assumes you are including the library with `#include "cryptsafe/cryptsafe.hpp"` in your source file.
  
4. If you have included the library using `#include <cryptsafe/cryptsafe.hpp>`, compile your file with this command instead:
######
    g++ -o main main.cpp -I. -L./cryptsafe -lcryptsafe -lcryptopp
  These instructions should help you successfully compile your program using the CryptSafe library.



