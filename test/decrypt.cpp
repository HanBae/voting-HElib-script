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

    amap.arg("o", owner, "owner's address");
    amap.parse(argc, argv);

    // file names
    const string secretKeyBinaryFileName = "data/secretKey/" + owner + ".bin";
    const string candidateFileName = "data/candidate/" + owner + "-" + to_string(number) + ".txt";

    ifstream secretBinFile(secretKeyBinaryFileName.c_str(), ios::binary);
    ifstream candidateFile(candidateFileName.c_str());

    // check open file
    assert(secretBinFile.is_open());
    assert(candidateFile.is_open());

    // Read in context,
    std::unique_ptr<FHEcontext> context = buildContextFromBinary(secretBinFile);
    readContextBinary(secretBinFile, *context);

    // Read in SecKey and PubKey.
    // Got to insert pubKey into seckey obj first.
    std::unique_ptr<FHESecKey> secKey(new FHESecKey(*context));
    FHEPubKey *pubKey = (FHEPubKey *) secKey.get();

    // read publicKey & secretKey
    readPubKeyBinary(secretBinFile, *pubKey);
    readSecKeyBinary(secretBinFile, *secKey);

    secretBinFile.close();

    cout << "read PublicKey & SecretKey successful.\n" << flush;

    // ready to decryption
    Ctxt encryptionText(*pubKey);
    ZZX resultPoly;

    // get Ctxt to file
    candidateFile >> encryptionText;

    // decrypt poly
    secKey->Decrypt(resultPoly, encryptionText);

    cout << "decryption successful.\n\n";

    cout << "result : "<< resultPoly << endl;
}