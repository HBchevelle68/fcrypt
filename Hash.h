#pragma once
#ifndef HASH_H
#define HASH_H

/*
@brief Header file for all hash wrapper functions
*/

#include <string>
#include <random>
#include <cryptopp565\osrng.h>
#include <cryptopp565\hex.h>
#include <cryptopp565\sha.h>
#include <cryptopp565\sha3.h>
#include <cryptopp565\files.h>
#include <cryptopp565\pwdbased.h>

//hash output sizes 
#define S512      128
#define S384      96
#define S256      64
#define SALTSIZE  8

namespace SafeSpace {
   namespace Hash {
      void SHA3_512(std::string& pwd, std::string& output, std::string& salt);
      void SHA3_384(std::string& pwd, std::string& output, std::string& salt);
      void SHA3_256(std::string& pwd, std::string& output, std::string& salt);
      void FileHash(std::fstream& file, std::string& outputHash);

      void GenSalt(std::string& pw_salt);
      void ByteToHexString(byte* b, std::string& salt);
      bool VerifyPw(std::string& pwd, const std::string& user_hash, std::string& salt);
   }
}



#endif