#include "cryptsafe.hpp"
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

namespace cryptsafe{

void Encrypt::encryptFile(const string &fileName, const string &encryptFileName, const string &publicKeyFile, const string &privateKeyFile){
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

string Encrypt::computeSHA256(const string &filename)
{
    SHA256 hash;
    string digest;

    FileSource file(filename.c_str(), true,
                    new HashFilter(hash,
                                   new HexEncoder(
                                       new StringSink(digest))));

    return digest;
}

void Encrypt::loadPrivateKey(const string &filename, RSA::PrivateKey &key)
{
    FileSource file(filename.c_str(), true);
    key.Load(file);
}

void Encrypt::loadPublicKey(const string &filename, RSA::PublicKey &key)
{
    FileSource file(filename.c_str(), true);
    key.Load(file);
}

string Encrypt::signHash(const string &hash, RSA::PrivateKey &privateKey)
{
    AutoSeededRandomPool rng;
    string signature;

    RSASS<PSS, SHA256>::Signer signer(privateKey);
    StringSource ss(hash, true,
                    new SignerFilter(rng, signer,
                                     new StringSink(signature)));

    return signature;
}

string Encrypt::encodeBase64(const string &binaryData)
{
    string encoded;
    StringSource ss(binaryData, true,
                    new Base64Encoder(
                        new StringSink(encoded)));

    return encoded;
}

SecByteBlock Encrypt::encryptAES(std::string& inputString, std::string& outputString) {
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

string Encrypt::encryptAESKey(const SecByteBlock &key, RSA::PublicKey &publicKey)
{
    AutoSeededRandomPool rng;
    string encryptedKey;

    RSAES<OAEP <SHA256> >::Encryptor encryptor(publicKey);
    StringSource ss(key.data(), key.size(), true,
                    new PK_EncryptorFilter(rng, encryptor,
                                           new StringSink(encryptedKey)));

    return encryptedKey;
}

void Decrypt::decryptFile(const string &fileName, const string &decryptFileName, const string &publicKeyFile, const string &privateKeyFile){
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
        cout << "Signature verification success!" << endl;
    }
    else cout << "Signature verification failed!" << endl;
}

vector<string> Decrypt::split(const string &s, char delimiter) {
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

string Decrypt::decodeBase64(const string& input) {
    string output;
    StringSource ss(input, true /*pumpAll*/,
        new Base64Decoder(
            new StringSink(output)
        )
    );
    return output;
}

bool Decrypt::verifySHA256(const string &hash, const string &signature, const RSA::PublicKey &publicKey)
{
    RSASS<PSS, SHA256>::Verifier verifier(publicKey);
    StringSource ss(hash + signature, true);

    return verifier.VerifyMessage((const CryptoPP::byte *)hash.data(), hash.size(),
                                  (const CryptoPP::byte *)signature.data(), signature.size());
}

void Decrypt::loadPrivateKey(const string &filename, RSA::PrivateKey &key)
{
    FileSource file(filename.c_str(), true);
    key.Load(file);
}

void Decrypt::loadPublicKey(const string &filename, RSA::PublicKey &key)
{
    FileSource file(filename.c_str(), true);
    key.Load(file);
}

SecByteBlock Decrypt::decryptAESKey(const std::string &encryptedKey, RSA::PrivateKey &privateKey)
{
    AutoSeededRandomPool rng;
    SecByteBlock decryptedKey(AES::DEFAULT_KEYLENGTH);

    RSAES<OAEP <SHA256> >::Decryptor decryptor(privateKey);
    StringSource ss2(encryptedKey, true,
                         new PK_DecryptorFilter(rng, decryptor,
                                                new ArraySink(decryptedKey, decryptedKey.size())));

    return decryptedKey;
}

void Decrypt::decryptAES(std::string& inputString, std::string& outputString, SecByteBlock key) {
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

void generateRSAKeyPair(const string& privateKeyFile, const string& publicKeyFile) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    RSA::PublicKey publicKey(privateKey);

    // Save private key
    privateKey.Save(FileSink(privateKeyFile.c_str(), true).Ref());

    // Save public key
    publicKey.Save(FileSink(publicKeyFile.c_str(), true).Ref());
}

} // namespace cryptsafe