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
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>
#include <cryptopp/base64.h>

using namespace std;
using namespace CryptoPP;


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

int main(){
    generateRSAKeyPair("private.txt","public.txt");

    return 0;
}