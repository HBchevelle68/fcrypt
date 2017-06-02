/*
   @Author - Anthony Portante
*/
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
#include "Hash.h"



namespace FCrypt {

   namespace KeyIO {
     
      void StoreToFile(size_t ksize, int pos, byte* iv, std::string& hash, std::string& salt, std::string& ofName);

      int Extract(std::string& ifName, std::string& extracted);
      bool Strip(std::string& toStrip, std::string& pwd, byte* key, size_t ksize, byte* iv, std::string& err);
      void stob(std::string& encoded, byte* barray, size_t bsize);
      void printBytes(byte * barray, size_t barraySize);
      inline void Move(CryptoPP::BufferedTransformation& bt, byte* out, size_t size) { bt.Get(out, size); }     
   }
}

#endif
