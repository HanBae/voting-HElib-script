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
    long c = 2;
    long w = 64;
    long L = 5;
    long cleanup = 1;

    string owner = "owner";

    amap.arg("m", m, "order of cyclotomic polynomial");
    amap.arg("p", p, "plaintext base");
    amap.arg("r", r, "lifting");
    amap.arg("c", c, "number of columns in the key-switching matrices");
    amap.arg("L", L, "number of levels wanted");
    amap.arg("cleanup", cleanup, "cleanup files created");
    amap.arg("o", owner, "owner's address");
    amap.parse(argc, argv);

    // file names
    const string secretKeyFile = "data/secretKey-" + owner + ".txt";
    const string secretKeyBinaryFile = "data/secretKey-" + owner + ".bin";
    const string publicKeyFile = "data/publicKey-" + owner + ".txt";
    const string publicKeyBinaryFile = "data/publicKey-" + owner + ".bin";

    ofstream secretAsciiFile(secretKeyFile.c_str());
    ofstream secretBinFile(secretKeyBinaryFile.c_str(), ios::binary);
    assert(secretAsciiFile.is_open());

    ofstream publicAsciiFile(publicKeyFile.c_str());
    ofstream publicBinFile(publicKeyBinaryFile.c_str(), ios::binary);
    assert(publicAsciiFile.is_open());

    // create context
    std::unique_ptr<FHEcontext> context(new FHEcontext(m, p, r));
    buildModChain(*context, L, c);  // Set the modulus chain

//        context->zMStar.printout(); // Printout context params
//        cout << "\tSecurity Level: " << context->securityLevel() << endl;

    // create key
    std::unique_ptr<FHESecKey> secKey(new FHESecKey(*context));
    FHEPubKey *pubKey = (FHEPubKey *) secKey.get();
    secKey->GenSecKey(w);
    addSome1DMatrices(*secKey);
    addFrbMatrices(*secKey);

    // Secret ASCII
    cout << "\tWriting Secret ASCII file " << secretKeyFile << endl;
    writeContextBase(secretAsciiFile, *context);
    secretAsciiFile << *context << endl << endl;
    secretAsciiFile << *pubKey << endl << endl;
    secretAsciiFile << *secKey << endl << endl;

    // Secret Bin
    cout << "\tWriting Secret Binary file " << secretKeyBinaryFile << endl;
    writeContextBaseBinary(secretBinFile, *context);
    writeContextBinary(secretBinFile, *context);
    writePubKeyBinary(secretBinFile, *pubKey);
    writeSecKeyBinary(secretBinFile, *secKey);

    // Public ASCII
    cout << "\tWriting Public ASCII file " << publicKeyFile << endl;
    writeContextBase(publicAsciiFile, *context);
    publicAsciiFile << *context << endl << endl;
    publicAsciiFile << *pubKey << endl << endl;

    // Public Bin
    cout << "\tWriting Public Binary file " << publicKeyBinaryFile << endl;
    writeContextBaseBinary(publicBinFile, *context);
    writeContextBinary(publicBinFile, *context);
    writePubKeyBinary(publicBinFile, *pubKey);

    secretAsciiFile.close();
    secretBinFile.close();
    publicAsciiFile.close();
    publicBinFile.close();

    cout << "createKey successful.\n\n";
}