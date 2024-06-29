#ifndef CRYPTSAFE_HPP
#define CRYPTSAFE_HPP

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/base64.h>

using namespace std;
using namespace CryptoPP;

namespace cryptsafe {
    
    void generateRSAKeyPair(const string& privateKeyFile, const string& publicKeyFile);

    class Encrypt {
        public:
            void encryptFile(const string &fileName, const string &encryptFileName, const string &publicKeyFile, const string &privateKeyFile);
        private:
            string computeSHA256(const string &filename);
            void loadPrivateKey(const string &filename, RSA::PrivateKey &key);
            void loadPublicKey(const string &filename, RSA::PublicKey &key);
            string signHash(const string &hash, RSA::PrivateKey &privateKey);
            string encodeBase64(const string &binaryData);
            SecByteBlock encryptAES(std::string& inputString, std::string& outputString);
            string encryptAESKey(const SecByteBlock &key, RSA::PublicKey &publicKey);
    };
    class Decrypt {
        public:
            void decryptFile(const string &fileName, const string &decryptFileName, const string &publicKeyFile, const string &privateKeyFile);
        private:
            vector<string> split(const string &s, char delimiter);
            string decodeBase64(const string& input);
            bool verifySHA256(const string &hash, const string &signature, const RSA::PublicKey &publicKey);
            void loadPrivateKey(const string &filename, RSA::PrivateKey &key);
            void loadPublicKey(const string &filename, RSA::PublicKey &key);
            SecByteBlock decryptAESKey(const std::string &encryptedKey, RSA::PrivateKey &privateKey);
            void decryptAES(std::string& inputString, std::string& outputString, SecByteBlock key);
    };
}





#endif // CRYPTSAFE_HPP