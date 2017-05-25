#pragma once
#ifndef RSA_H
#define RSA_H


#include <crypto++/osrng.h>
#include <crypto++/rsa.h>
#include <crypto++/files.h>
#include <crypto++/base64.h>
#include <crypto++/hex.h>

//Key sizes (bits)
#define WEAK     1024
#define NORM     2048
#define STRONG   3072
#define Y_THO    4096
#define PLS_KYS  8192


namespace FCrypt {
   namespace RSA {

      void GenKeyPair(CryptoPP::RSA::PrivateKey& priv, CryptoPP::RSA::PublicKey& pub, const size_t keySize);
      void EncryptString(CryptoPP::RSA::PublicKey& pub, std::string& plain, std::string& cipher);
      void DecryptString(CryptoPP::RSA::PrivateKey& priv, std::string& cipher, std::string& plain);

      // Moved key IO functions to KeyIO.h/KeyIO.cpp

   }

}







#endif
