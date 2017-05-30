/*
@brief implementation file for all hash wrapper functions

ALL hash functions are updated to newest algs version -> SHA3
*/

#include "Hash.h"



namespace SafeSpace {
   namespace Hash {
      
      /* Password Based Key Derivation Function
      @brief PBKDF function provides a hash over many iterations that "sstretches" the "key" or password

      @param pwd a reference to the entered password
      @param salt refernce to users salt value
      @param result, output string of "stretched" key
      @param iter number of iterations function should perform, default 1000
      */
      void PKCS5_PBKDF2(std::string& pwd, std::string& salt, std::string& result, size_t iter = 1000) {

         byte derived[128]; //Stretch "key" (pwd) to this size

         CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;
         pbkdf2.DeriveKey(derived, sizeof(derived), 0, (unsigned char*)pwd.c_str(),
            pwd.length(), (unsigned char*)salt.c_str(), SALTSIZE, iter);

         //Transforms from byte to string
         CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
         encoder.Put(derived, sizeof(derived));
         encoder.MessageEnd();
         //At this point a string version of the hash is in result
         //and a byte array of hash is in derived
      }

      /* SHA-512 HASH
      @brief Function takes in a reference to a password string and a reference to
      a return string and generates a SHA-512 hash. Hash scheme is suitable
      for DoD level usage.

      @param pwd a reference to the entered password
      @param output return variable with sha3-512 hash
      @param salt refernce to users salt value
      */
      void SHA3_512(std::string& pwd, std::string& output, std::string& salt)
      {
         if (salt.empty()) {
            GenSalt(salt);
            pwd.append(salt);
         }
         else {
            pwd.append(salt);
         }
         CryptoPP::SHA3_512 sha3_512;
         CryptoPP::StringSource(pwd, true,
            new CryptoPP::HashFilter(sha3_512,
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
      }
      /* SHA-384 HASH
      @brief Function takes in a reference to a password string and a reference to
      a return string and generates a SHA-384 hash.

      @param pwd a reference to the entered password
      @param output return variable with sha3-384 hash
      @param salt refernce to users salt value
      */
      void SHA3_384(std::string& pwd, std::string& output, std::string& salt)
      {
         if (salt.empty()) {
            GenSalt(salt);
            pwd.append(salt);
         }
         else {
            pwd.append(salt);
         }
         CryptoPP::SHA3_384 sha3_384;
         CryptoPP::StringSource(pwd, true,
            new CryptoPP::HashFilter(sha3_384,
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
      }
      /* SHA-256 HASH
      @brief Function takes in a reference to a password string and a reference to
      a return string and generates a SHA-256 hash.

      @param pwd a reference to the entered password
      @param output return variable with sha3-256 hash
      @param salt refernce to users salt value
      */
      void SHA3_256(std::string& pwd, std::string& output, std::string& salt)
      {
         if (salt.empty()) {
            GenSalt(salt);
            pwd.append(salt);
         }
         else {
            pwd.append(salt);
         }
         CryptoPP::SHA3_256 sha3_256;
         CryptoPP::StringSource(pwd, true,
            new CryptoPP::HashFilter(sha3_256,
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
      }

      void FileHash(std::fstream & file, std::string & outputHash)
      {
         CryptoPP::SHA3_256 sha3_256;
         CryptoPP::FileSource(file, true, 
            new CryptoPP::HashFilter(sha3_256, 
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(outputHash))));
      }

      /* Byte Array to std::string
      @brief Function accepts the entered password, and users hash. Generates hash on
      entered password, then compares to verify correct password

      @param bArray byte array pointer to byte array containing raw version of salt
      @param salt refernce to output string for finished version of salt
      */
      void ByteToHexString(byte* bArray, std::string& salt) {
         char hexBuf[3];
         for (int i = 0; i < SALTSIZE; ++i) {
            sprintf_s(hexBuf, "%02X", bArray[i]);
            salt += hexBuf;
         }
      }

      /* Password Salt Generation
      @brief Function accepts the entered password, and users hash. Generates hash on
      entered password, then compares to verify correct password

      @param pw_salt a reference to the salt(string). After generation it is converted
      from hex to string
      */
      void GenSalt(std::string& pw_salt)
      {
         CryptoPP::AutoSeededRandomPool prng;
         byte temp[SALTSIZE];
         prng.GenerateBlock(temp, SALTSIZE);
         ByteToHexString(temp, pw_salt);
      }

      /* Password verification
      @brief Function accepts the entered password, and users hash. Generates hash on
      entered password, then compares to verify correct password

      @param pwd a reference to the entered password
      @param user_hash reference to users hash, baseline for comparision
      @param salt refernce to users salt value, required for proper comparison

      @return true if password is a match, false if not a match

      */
      bool VerifyPw(std::string& pwd, const std::string& user_hash, std::string& salt)
      {
         std::string temp;
         if (user_hash.length() == S512) { SHA3_512(pwd, temp, salt); }
         else if (user_hash.length() == S384) { SHA3_384(pwd, temp, salt); }
         else { SHA3_256(pwd, temp, salt); }
         return (!user_hash.compare(temp)) ? true : false;
      }

   }
}





