#pragma once
#ifndef KEYIO_H
#define KEYIO_H

#include <crypto++/rsa.h>
#include <crypto++/files.h>
#include <crypto++/base64.h>
#include <crypto++/hex.h>
#include <crypto++/aes.h>
#include <crypto++/ccm.h>


namespace FCrypt {
   namespace KeyIO {
     

      void EncryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* keyToEnc, const size_t ktoEncSize, byte* out);
      void DecryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* toDecrypt, const size_t toDecSize, byte* decrypted);
      void KIVbtos(byte* key, size_t ksize, byte* iv, size_t vsize, std::string& kStr, std::string& ivStr);


      inline void Move(CryptoPP::BufferedTransformation& bt, byte* out, size_t size) { bt.Get(out, size); }
   }
}





#endif
