/*
   @Author - Anthony Portante
*/
#pragma once
#ifndef AES_H
#define AES_H

#include <iostream>
#include <string>
#include <fstream>
#include <random>

#include <crypto++/cryptlib.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/ccm.h>
#include <crypto++/osrng.h>
#include <crypto++/files.h>

#include "Hash.h"

#define AES128 CryptoPP::AES::DEFAULT_KEYLENGTH //128-bit
#define AES192 24                               //192-bit
#define AES256 CryptoPP::AES::MAX_KEYLENGTH     //256-bit
#define IVSIZE CryptoPP::AES::BLOCKSIZE

namespace FCrypt {
   
   namespace AES {
      void GenKeyIv(byte* key, size_t ksize, byte* iv, size_t vsize);
      void UserGen(std::string& pwd, std::string& salt, std::string& hash, byte* key, size_t ksize, byte* iv, int& pos);
      void KeyToStr(byte* key, size_t ksize, std::string& out);
      void IvToStr(byte* iv, size_t vsize, std::string& out);
      int genRand(int lower, int upper);

      bool EncryptFile(std::ifstream& inFile,
         std::ofstream& outFile,
         const byte* key, size_t ksize,
         const byte* iv, size_t vsize,
         std::string& errMsg);

      bool DecryptFile(std::ifstream& inFile,
         std::ofstream& outFile,
         const byte* key, size_t ksize,
         const byte* iv, size_t vsize,
         std::string& errMsg);
   }
}



#endif
