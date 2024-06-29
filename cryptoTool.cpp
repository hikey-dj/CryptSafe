#include <iostream>
#include <fstream>
#include <string>
#include "cryptsafe/cryptsafe.hpp"

using namespace std;
using namespace cryptsafe;

int main(int argc,char* argv[]){
    string option = argv[1];
    if(option == "-key"){
        generateRSAKeyPair("private.txt","public.txt");
    }
    else if(option == "-enc"){
        Encrypt enc;
        string filename = argv[2];
        string recipientPublicKeyFile = argv[3];
        string senderPrivateKeyFile = argv[4];
        enc.encryptFile(filename, "encryptedFile.bin", recipientPublicKeyFile, senderPrivateKeyFile);
    }
    else if(option == "-dec"){
        Decrypt dec;
        string encryptedFilename = argv[2];
        string senderPublicKeyFile = argv[3];
        string recipientPrivateKeyFile = argv[4];
        dec.decryptFile(encryptedFilename, "decryptedFile.txt", senderPublicKeyFile, recipientPrivateKeyFile);
    }
    else if(option == "-help"){
        cout << "Usage:\n\t./encryption -key \n\t-enc <filename> <recipient-public-key-file> <sender-private-key-file> \n\t-dec <filename> <sender-public-key-file> <recipient-private-key-file>" << endl;
    }
    else{
        cout << "Invalid option type -help to know more" << endl;
    }
}