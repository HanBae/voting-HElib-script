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

    long n = 4;

    string owner = "owner";
    string resultCtxtFileName = "data/owner-result.txt";

    amap.arg("o", owner, "owner's address");
    amap.arg("r", resultCtxtFileName, "result Ctxt file's name");
    amap.arg("n", n, "number of add files");
    amap.parse(argc, argv);

    // file names
    const string secretKeyBinaryFileName = "data/secretKey/" + owner + ".bin";

    ifstream secretBinFile(secretKeyBinaryFileName.c_str(), ios::binary);
    fstream CtxtFiles[n];
    for(long i = 0; i < n; i++) {
        string fileName = "data/candidate/" + owner + "-" + to_string(i) + ".txt";
        CtxtFiles[i] = fstream(fileName.c_str(), fstream::in);
        assert(CtxtFiles[i].is_open());
    }
    ofstream resultCtxtFile(resultCtxtFileName.c_str(), ios::binary);

    // check open file
    assert(secretBinFile.is_open());
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
    // get Ctxt to file
    Ctxt resultCtxt(*pubKey), secondCtxt(*pubKey);
    CtxtFiles[0] >> resultCtxt;

    // add files
    for(long i = 1; i < n; i++) {
        CtxtFiles[i] >> secondCtxt;
        resultCtxt += secondCtxt;
    }

    // show result
    ZZX ptSum;
    secKey->Decrypt(ptSum, resultCtxt);
    cout << "result : " << ptSum <<endl;

    // save resultCtxt
    resultCtxtFile << resultCtxt << endl;
}