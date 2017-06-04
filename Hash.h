#pragma once
#ifndef HASH_H
#define HASH_H

/*
@brief Header file for all hash wrapper functions
*/

#include <string>
#include <random>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>
#include <crypto++/sha.h>
#include <crypto++/files.h>
#include <crypto++/pwdbased.h>

#include "KeyIO.h"

//hash output sizes 
#define S512      128
#define S384      96
#define S256      64
#define SALTSIZE  8

namespace FCrypt {

   namespace Hash {

      void SHA_512(std::string& pwd, std::string& output, std::string& salt);
      void SHA_384(std::string& pwd, std::string& output, std::string& salt);
      void SHA_256(std::string& pwd, std::string& output, std::string& salt);
      void PKCS5_PBKDF2(std::string& pwd, std::string& salt, byte* key, size_t ksize, int pos, size_t iter = 1000);
      void FileHash(std::fstream& file, std::string& outputHash);

      void GenSalt(std::string& pw_salt);
      void ByteToHexString(byte* b, std::string& salt);
   }
}



#endif