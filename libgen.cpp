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

class Encrypt {
    public:
        void encryptFile(const string &fileName, const string &encryptFileName, const string &publicKeyFile, const string &privateKeyFile){
            string hash = computeSHA256(fileName);
            RSA::PrivateKey privateKey;
            loadPrivateKey(privateKeyFile, privateKey);
            string signature = signHash(hash, privateKey);
            string encodedSignature = encodeBase64(signature);

            ifstream file(fileName);
            string contents((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            string inputString = contents;
            string outputString = "";
            SecByteBlock key = encryptAES(inputString, outputString);
            RSA::PublicKey publicKey;
            loadPublicKey(publicKeyFile, publicKey);
            string encrypted_AES_key = encryptAESKey(key , publicKey); 
            string readable_AES_key = encodeBase64(encrypted_AES_key);             
            outputString = encodedSignature + ":" +encodeBase64(hash) + ":" + readable_AES_key + ":" + outputString;
            ofstream encryptedFile(encryptFileName);
            encryptedFile << outputString;
        }

    private:
        string computeSHA256(const string &filename)
        {
            SHA256 hash;
            string digest;

            FileSource file(filename.c_str(), true,
                            new HashFilter(hash,
                                           new HexEncoder(
                                               new StringSink(digest))));

            return digest;
        }

        // Function to load RSA private key from a file
        void loadPrivateKey(const string &filename, RSA::PrivateKey &key)
        {
            FileSource file(filename.c_str(), true);
            key.Load(file);
        }

        // Function to load RSA public key from a file
        void loadPublicKey(const string &filename, RSA::PublicKey &key)
        {
            FileSource file(filename.c_str(), true);
            key.Load(file);
        }
        string signHash(const string &hash, RSA::PrivateKey &privateKey)
        {
            AutoSeededRandomPool rng;
            string signature;

            RSASS<PSS, SHA256>::Signer signer(privateKey);
            StringSource ss(hash, true,
                            new SignerFilter(rng, signer,
                                             new StringSink(signature)));

            return signature;
        }
        // Function to encode signature in Base64
        string encodeBase64(const string &binaryData)
        {
            string encoded;
            StringSource ss(binaryData, true,
                            new Base64Encoder(
                                new StringSink(encoded)));

            return encoded;
        }
        SecByteBlock encryptAES(std::string& inputString, std::string& outputString) {
            AutoSeededRandomPool pool;
            SecByteBlock key(AES::DEFAULT_KEYLENGTH);
            pool.GenerateBlock(key, key.size());

            CryptoPP::byte iv[AES::BLOCKSIZE];
            pool.GenerateBlock(iv, AES::BLOCKSIZE);

            CBC_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            StringSource fs(
                inputString,
                true,
                new StreamTransformationFilter(
                    encryptor,
                    new StringSink(outputString)
                )
            );

            outputString = string((char*)iv, AES::BLOCKSIZE) + outputString;

            return key;
        }

        string encryptAESKey(const SecByteBlock &key, RSA::PublicKey &publicKey)
        {
            AutoSeededRandomPool rng;
            string encryptedKey;

            RSAES<OAEP <SHA256> >::Encryptor encryptor(publicKey);
            StringSource ss(key.data(), key.size(), true,
                            new PK_EncryptorFilter(rng, encryptor,
                                                   new StringSink(encryptedKey)));

            return encryptedKey;
        }
};

class Decrypt {
    public:
        void decryptFile(const string &fileName, const string &decryptFileName, const string &publicKeyFile, const string &privateKeyFile){
            ifstream file(fileName);
            string contents((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            string rawInputString = contents;
            vector<string> tokens = split(rawInputString, ':');
            string signature = decodeBase64(tokens[0]);
            string hash = decodeBase64(tokens[1]);
            string encryptedKey = decodeBase64(tokens[2]);
            string encryptedMessage = "";
            for(int i=3; i<tokens.size(); i++) {
                encryptedMessage += tokens[i];
            }

            RSA::PrivateKey privateKey;
            loadPrivateKey(privateKeyFile, privateKey);
            RSA::PublicKey publicKey;
            loadPublicKey(publicKeyFile, publicKey);

            SecByteBlock decryptedKey = decryptAESKey(encryptedKey, privateKey);
            string decryptedOutput = "";
            decryptAES(encryptedMessage, decryptedOutput, decryptedKey);

            bool verify = verifySHA256(hash, signature, publicKey);
            if (verify){
                ofstream decryptedFile(decryptFileName);
                decryptedFile << decryptedOutput;
            }
            else cout << "Signature verification failed!" << endl;
        }

    private:
        vector<string> split(const string &s, char delimiter) {
            vector<string> tokens;
            for(int i=0; i < s.size(); i++) {
                string token = "";
                while(s[i] != delimiter && i < s.size()) {
                    token += s[i];
                    i++;
                }
                tokens.push_back(token);
            }
            return tokens;
        }

        string decodeBase64(const string& input) {
            string output;
            StringSource ss(input, true /*pumpAll*/,
                new Base64Decoder(
                    new StringSink(output)
                )
            );
            return output;
        }        

        bool verifySHA256(const string &hash, const string &signature, const RSA::PublicKey &publicKey)
        {
            RSASS<PSS, SHA256>::Verifier verifier(publicKey);
            StringSource ss(hash + signature, true);

            return verifier.VerifyMessage((const CryptoPP::byte *)hash.data(), hash.size(),
                                          (const CryptoPP::byte *)signature.data(), signature.size());
        }
        void loadPrivateKey(const string &filename, RSA::PrivateKey &key)
        {
            FileSource file(filename.c_str(), true);
            key.Load(file);
        }

        // Function to load RSA public key from a file
        void loadPublicKey(const string &filename, RSA::PublicKey &key)
        {
            FileSource file(filename.c_str(), true);
            key.Load(file);
        }
        SecByteBlock decryptAESKey(const std::string &encryptedKey, RSA::PrivateKey &privateKey)
        {
            
            

            // Decrypt the AES key
            AutoSeededRandomPool rng;
            SecByteBlock decryptedKey(AES::DEFAULT_KEYLENGTH);

            RSAES<OAEP <SHA256> >::Decryptor decryptor(privateKey);
            StringSource ss2(encryptedKey, true,
                                 new PK_DecryptorFilter(rng, decryptor,
                                                        new ArraySink(decryptedKey, decryptedKey.size())));

            return decryptedKey;
        }
        void decryptAES(std::string& inputString, std::string& outputString, SecByteBlock key) {
            CryptoPP::byte iv[AES::BLOCKSIZE];
            memcpy(iv, inputString.c_str(), AES::BLOCKSIZE);

            CBC_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            StringSource fs(
                inputString.substr(AES::BLOCKSIZE),
                true,
                new StreamTransformationFilter(
                    decryptor,
                    new StringSink(outputString)
                )
            );
        }
};

extern "C" {
    Encrypt * Encrypt_new() { return new Encrypt(); }
    void encryptFile_C(Encrypt * enc, const char *fileName, const char *encryptFileName, const char *publicKeyFile, const char *privateKeyFile) {
        enc->encryptFile(string(fileName), string(encryptFileName), string(publicKeyFile), string(privateKeyFile));
    }
    Decrypt * Decrypt_new() { return new Decrypt(); }
    void decryptFile_C(Decrypt * dec, const char *fileName, const char *decryptFileName, const char *publicKeyFile, const char *privateKeyFile) {
        dec->decryptFile(string(fileName), string(decryptFileName), string(publicKeyFile), string(privateKeyFile));
    }
    void Encrypt_delete(Encrypt * enc) { delete enc; }
    void Decrypt_delete(Decrypt * dec) { delete dec; }
}

int main() {
    Encrypt enc;
    string filename = "test.txt";
    string encryptedFilename = "encryptedfile.bin";
    string masterPassword = "your-master-password";
    string privateKeyFile = "private.txt";
    string publicKeyFile = "public.txt";

    enc.encryptFile(filename, encryptedFilename, publicKeyFile, privateKeyFile);

    Decrypt dec;
    string decryptedFilename = "decryptedfile.txt";
    dec.decryptFile(encryptedFilename, decryptedFilename, publicKeyFile, privateKeyFile);

    return 0;
}