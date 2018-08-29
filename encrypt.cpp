#include <cstring>
#include <fstream>
#include <unistd.h>

#include <NTL/ZZX.h>
#include <NTL/vector.h>

#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"

int main(int argc, char *argv[]) {
    ArgMapping amap;

    long m = 7;
    long r = 1;
    long p = 65537;
    long cleanup = 1;

    string owner = "owner";
    long number = 1;
    long total = 4;

    amap.arg("o", owner, "owner's address");
    amap.arg("n", number, "candidate's number");
    amap.arg("t", total, "candidate's total number");
    amap.parse(argc, argv);

    // file names
    const string publicKeyBinaryFileName = "data/publicKey-" + owner + ".bin";
    const string candidateFileName = "data/candidates-" + to_string(number) + "-" + owner + ".txt";

    ifstream publicBinFile(publicKeyBinaryFileName.c_str(), ios::binary);
    fstream candidateFile(candidateFileName.c_str(), fstream::out|fstream::trunc);

    // check open file
    assert(publicBinFile.is_open());
    assert(candidateFile.is_open());

    // Read in context,
    std::unique_ptr<FHEcontext> context = buildContextFromBinary(publicBinFile);
    readContextBinary(publicBinFile, *context);

    // Read in SecKey and PubKey.
    // Got to insert pubKey into seckey obj first.
    std::unique_ptr<FHESecKey> secKey(new FHESecKey(*context));
    FHEPubKey *pubKey = (FHEPubKey *) secKey.get();

    // read publicKey
    readPubKeyBinary(publicBinFile, *pubKey);

    cout << "read publicKey successful.\n" << flush;

    // ready to encryption
    Ctxt encryptionText(*pubKey);
    Vec<ZZ> resultPoly;
    resultPoly.SetLength(total);

    // set poly
    for(long i = 0; i < total; i++) {
        if(i == number-1) resultPoly[i] = 1;
        else resultPoly[i] = 0;
    }

    // encrypt poly
    pubKey->Encrypt(encryptionText, to_ZZX(resultPoly));
    candidateFile << encryptionText << endl;

    cout << "array : " << resultPoly << endl;

    cout << "encryption candidate successful.\n\n";
}