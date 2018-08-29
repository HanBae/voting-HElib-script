#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>
#include <iostream>
#include <ctime>
using namespace std;

Ctxt FHE_Add(Ctxt Ea, Ctxt Eb)
{
    Ctxt ctSum = Ea;
    ctSum += Eb;
    return ctSum;
}

Ctxt FHE_Mul(Ctxt Ea, Ctxt Eb)
{
    Ctxt ctMul = Ea;
    ctMul *= Eb;
    return ctMul;
}

int main()
{

    clock_t start = clock();

    long m = 0;
    long p = 1021;
    long r = 2;
    long L = 16;
    long c = 3;
    long w = 64;
    long d = 0;
    long k = 128;
    long s = 0;

    m = FindM(k, L, c, p, d, s, 0);

    FHEcontext context(m, p, r);
    buildModChain(context, L, c);
    printf("Chain:%0.5f\n",(float)(clock() - start)/CLOCKS_PER_SEC);

    FHESecKey secretKey(context);
    const FHEPubKey& publicKey = secretKey;
    secretKey.GenSecKey(w);
    printf("GenSecKey:%0.5f\n",(float)(clock() - start)/CLOCKS_PER_SEC);

    cout << "======= Secret Key ======= \n" << secretKey << endl;
    cout << "======= Public Key ======= \n" << publicKey << endl;

    Ctxt Ea(publicKey);
    Ctxt Eb(publicKey);

    Vec<ZZ> h;
    h.SetLength(4);
    h[0]=1;
    h[1]=1;
    h[2]=1;
    h[3]=1;

    Vec<ZZ> t;
    t.SetLength(4);
    t[0]=1;
    t[1]=0;
    t[2]=0;
    t[3]=0;

    publicKey.Encrypt(Ea, to_ZZX(h));
    publicKey.Encrypt(Eb, to_ZZX(t));

    ZZX ptSum;
    Ctxt ctSum = Ea;

    for(int i =0; i<10; i++) {
        ctSum = FHE_Add(ctSum, Eb);
    }
    secretKey.Decrypt(ptSum, ctSum);
    cout << "ptSum : " << ptSum <<endl;
    printf("%0.5f\n",(float)(clock() - start)/CLOCKS_PER_SEC);

    for(int j =0; j<100; j++) {
        ctSum = FHE_Add(ctSum, Eb);
    }
    secretKey.Decrypt(ptSum, ctSum);
    cout << "ptSum : " << ptSum <<endl;
    printf("%0.5f\n",(float)(clock() - start)/CLOCKS_PER_SEC);

    for(int as =0; as<1000; as++) {
        ctSum = FHE_Add(ctSum, Eb);
    }
    secretKey.Decrypt(ptSum, ctSum);
    cout << "ptSum : " << ptSum <<endl;
    printf("%0.5f\n",(float)(clock() - start)/CLOCKS_PER_SEC);

/*
	ZZX ptSum;
	Ctxt ctSum = FHE_Add(Ea, Eb);
	secretKey.Decrypt(ptSum, ctSum);
	cout << "ptSum : " << ptSum <<endl;

	ZZX ptMul;
	Ctxt ctMul = FHE_Mul(Ea, Eb);
	secretKey.Decrypt(ptMul, ctMul);
	cout << "ptMul : " << ptMul <<endl;
	ZZX ptSub;
	secretKey.Decrypt(ptSub, FHE_Sub(Ea, Eb, publicKey));
	cout << "ptSub : " << ptSub <<endl;
*/
    return 0;
}