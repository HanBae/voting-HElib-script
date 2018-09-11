#include <cstring>
#include <fstream>
#include <unistd.h>

#include <NTL/ZZX.h>
#include <NTL/vector.h>

#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"

Ctxt FHE_Add(Ctxt Ea, Ctxt Eb)
{
    Ctxt ctSum = Ea;
    ctSum += Eb;
    return ctSum;
}

int main(int argc, char *argv[]) {
    ArgMapping amap;

    string owner = "owner";
    string firstCtxtFileName = "data/candidate/owner-0.txt";
    string secondCtxtFileName = "data/candidate/owner-1.txt";
    string resultCtxtFileName = "data/owner-result.txt";

    amap.arg("o", owner, "owner's address");
    amap.arg("f", firstCtxtFileName, "first Ctxt file's name");
    amap.arg("s", secondCtxtFileName, "second Ctxt file's name");
    amap.arg("r", resultCtxtFileName, "result Ctxt file's name");
    amap.parse(argc, argv);

    // file names
    const string secretKeyBinaryFileName = "data/secretKey/" + owner + ".bin";

    ifstream secretBinFile(secretKeyBinaryFileName.c_str(), ios::binary);
    ifstream firstCtxtFile(firstCtxtFileName.c_str(), ios::binary);
    ifstream secondCtxtFile(secondCtxtFileName.c_str(), ios::binary);
    ofstream resultCtxtFile(resultCtxtFileName.c_str(), ios::binary);

    // check open file
    assert(secretBinFile.is_open());
    assert(firstCtxtFile.is_open());
    assert(secondCtxtFile.is_open());
    assert(resultCtxtFile.is_open());

    // Read in context,
    std::unique_ptr<FHEcontext> context = buildContextFromBinary(secretBinFile);
    readContextBinary(secretBinFile, *context);

    // Read in SecKey and PubKey.
    // Got to insert pubKey into seckey obj first.
    std::unique_ptr<FHESecKey> secKey(new FHESecKey(*context));
    FHEPubKey *pubKey = (FHEPubKey *) secKey.get();

    // read publicKey
    readPubKeyBinary(secretBinFile, *pubKey);
    readSecKeyBinary(secretBinFile, *secKey);

    secretBinFile.close();

    cout << "read PublicKey & SecretKey successful.\n" << flush;

    // ready to add two Ctxts
    Ctxt firstCtxt(*pubKey);
    Ctxt secondCtxt(*pubKey);

    // get Ctxt to file
    firstCtxtFile >> firstCtxt;
    secondCtxtFile >> secondCtxt;

    // add two Ctxt
    Ctxt resultCtxt = FHE_Add(firstCtxt, secondCtxt);

    // show result
    ZZX ptSum;
    secKey->Decrypt(ptSum, resultCtxt);
    cout << "result : " << ptSum <<endl;

    // save resultCtxt
    resultCtxtFile << resultCtxt << endl;
}