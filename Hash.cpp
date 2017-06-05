/*
@brief implementation file for all hash wrapper functions
*/

#include "Hash.h"


namespace FCrypt {
   
   namespace Hash {
      
      /* Password Based Key Derivation Function
      @brief PBKDF2 function provides a hash over many iterations 
             that "stretches" the "key" or password. Algorithm won
             RSA/IETF competition for PBKDF to replace old PBKDF.

      @param pwd a reference to the entered password
      @param salt refernce to users salt value
      @param result, output string of "stretched" key
      @param iter number of iterations function should perform, default 1000
      */
      void PKCS5_PBKDF2(std::string& pwd, std::string& salt, byte* key, size_t ksize, int pos, size_t iter) {

         byte derived[1000]; //Stretch "key" (pwd) to this size

         CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
         pbkdf2.DeriveKey(derived, sizeof(derived), 0, (unsigned char*)pwd.c_str(),
            pwd.length(), (unsigned char*)salt.c_str(), SALTSIZE, iter);

         memcpy(key, &derived[pos], ksize);
      }

      /* SHA-512 HASH
      @brief Function takes in a reference to a password string and a reference to
      a return string and generates a SHA-512 hash. Hash scheme is suitable
      for DoD level usage.

      @param pwd a reference to the entered password
      @param output return variable with sha3-512 hash
      @param salt refernce to users salt value
      */
      void SHA_512(std::string& pwd, std::string& output, std::string& salt){
         if (salt.empty()) {
            GenSalt(salt);
            pwd.append(salt);
         }
         else {
            pwd.append(salt);
         }
         CryptoPP::SHA512 sha_512;
         CryptoPP::StringSource(pwd, true,
            new CryptoPP::HashFilter(sha_512,
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
      }
      /* SHA-384 HASH
      @brief Function takes in a reference to a password string and a reference to
      a return string and generates a SHA-384 hash.

      @param pwd a reference to the entered password
      @param output return variable with sha3-384 hash
      @param salt refernce to users salt value
      */
      void SHA_384(std::string& pwd, std::string& output, std::string& salt){
         if (salt.empty()) {
            GenSalt(salt);
            pwd.append(salt);
         }
         else {
            pwd.append(salt);
         }
         CryptoPP::SHA384 sha_384;
         CryptoPP::StringSource(pwd, true,
            new CryptoPP::HashFilter(sha_384,
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
      }
      /* SHA-256 HASH
      @brief Function takes in a reference to a password string and a reference to
      a return string and generates a SHA-256 hash.

      @param pwd a reference to the entered password
      @param output return variable with sha3-256 hash
      @param salt refernce to users salt value
      */
      void SHA_256(std::string& pwd, std::string& output, std::string& salt){
         if (salt.empty()) {
            GenSalt(salt);
            pwd.append(salt);
         }
         else {
            pwd.append(salt);
         }
         CryptoPP::SHA256 sha_256;
         CryptoPP::StringSource(pwd, true,
            new CryptoPP::HashFilter(sha_256,
               new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
      }

      void FileHash(std::ifstream& file, std::string& outputHash){
         
         CryptoPP::SHA256 sha_256;
         CryptoPP::FileSource(file, true, 
            new CryptoPP::HashFilter(sha_256, 
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
            sprintf(hexBuf, "%02X", bArray[i]);
            salt += hexBuf;
         }
      }

      /* Password Salt Generation
      @brief Function accepts the entered password, and users hash. Generates hash on
      entered password, then compares to verify correct password

      @param pw_salt a reference to the salt(string). After generation it is converted
      from hex to string
      */
      void GenSalt(std::string& pw_salt){
         CryptoPP::AutoSeededRandomPool prng;
         byte temp[SALTSIZE];
         prng.GenerateBlock(temp, SALTSIZE);
         ByteToHexString(temp, pw_salt);
      }

   }
}





