#include <cstring>
#include <fstream>
#include <unistd.h>

#include <NTL/ZZX.h>
#include <NTL/vector.h>

#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"

/**
 *  키를 생성하여 파일로 내보내는 모듈.
 *
 *  원래 RSA 방식과는 다르게 비밀키에서 공개키를 생성하는 구조임.
 *  공개키로 암호화를 하고, 비밀키로 복호화를 함.
 *
 *  키마다 txt파일(ascii)과 bin파일의 두 파일로 내보내짐
 *  공개키 : FHEcontext와 FHEPubKey 두 객체를 내보냄
 *  비밀키 : FHEcontext, FHESecKey 두 객체를 내보냄
 *
 */
int main(int argc, char *argv[]) {

    ArgMapping amap;

    long m = 7;
    long r = 1;
    long p = 65537;
    long c = 2;
    long w = 64;
    long L = 5;
    long k = 80;
    long d = 1;
    long s = 0;
    long cleanup = 1;

    string owner = "owner";

    amap.arg("p", p, "plaintext base");
    amap.arg("r", r, "lifting");
    amap.arg("c", c, "number of columns in the key-switching matrices");
    amap.arg("L", L, "number of levels wanted");
    amap.arg("cleanup", cleanup, "cleanup files created");
    amap.arg("o", owner, "owner's address");
    amap.parse(argc, argv);

    // file names
    const string secretKeyFile = "data/secretKey/" + owner + ".txt";
    const string secretKeyBinaryFile = "data/secretKey/" + owner + ".bin";
    const string publicKeyFile = "data/publicKey/" + owner + ".txt";
    const string publicKeyBinaryFile = "data/publicKey/" + owner + ".bin";

    ofstream secretAsciiFile(secretKeyFile.c_str());
    ofstream secretBinFile(secretKeyBinaryFile.c_str(), ios::binary);
    assert(secretAsciiFile.is_open());

    ofstream publicAsciiFile(publicKeyFile.c_str());
    ofstream publicBinFile(publicKeyBinaryFile.c_str(), ios::binary);
    assert(publicAsciiFile.is_open());

    m = FindM(k, L, c, p, d, s, 0);

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
    secretAsciiFile << *secKey << endl << endl;

    // Secret Bin
    cout << "\tWriting Secret Binary file " << secretKeyBinaryFile << endl;
    writeContextBaseBinary(secretBinFile, *context);
    writeContextBinary(secretBinFile, *context);
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