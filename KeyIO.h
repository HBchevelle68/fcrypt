#pragma once
#ifndef KEYIO_H
#define KEYIO_H


#include <crypto++/rsa.h>
#include <crypto++/files.h>
#include <crypto++/base64.h>
#include <crypto++/hex.h>
#include <crypto++/aes.h>
#include <crypto++/ccm.h>

#include "AES.h"



namespace FCrypt {
   namespace KeyIO {
     

      void EncryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* keyToEnc, const size_t ktoEncSize, byte* out);
      void DecryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* toDecrypt, const size_t toDecSize, byte* decrypted);
      void KIVtof(byte* key, size_t ksize, byte* iv, size_t vsize, std::string& ofName);
      void WriteToFile(std::string& ofName, size_t encSize, std::string& kStr, std::string& ivStr);

      int ExtractKIV(std::string& ofName, std::string& extracted);
      
      void Strip(std::string& toStrip, byte* key, size_t ksize, byte* iv);
      void stob(std::string& encoded, byte* barray, size_t len);

      inline void Move(CryptoPP::BufferedTransformation& bt, byte* out, size_t size) { bt.Get(out, size); }
      void printBytes(byte * barray, size_t barraySize);
   }
}





#endif
