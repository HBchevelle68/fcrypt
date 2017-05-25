#include "AES.h"


namespace FCrypt {

   namespace AES {

      /*
      @brief generates an initialization vector and key

      @param key the reference of the key being generated
      @param ksize the size of the key generated
      @param iv the reference of the IV being generated
      @param vsize the size of the IV being generated
      */
      void GenKeyIv(byte* key, size_t ksize, byte* iv, size_t vsize)
      {
         CryptoPP::AutoSeededRandomPool prng;
         prng.GenerateBlock(key, ksize);
         prng.GenerateBlock(iv, vsize);
      }

      /*
      @brief Converts the key to a string

      @param key key being converted to a string
      @param ksize size of the key
      @param out the key in string format
      */
      
      void KeyToStr(byte* key, size_t ksize, std::string& out){
         out.clear();
         CryptoPP::StringSource(key, ksize, true,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(out)));
      }
   
      /*
      @brief Converts the Initialization Vector to a string

      @param iv IV being converted to a string
      @param vsize size of the IV
      @param out the IV in string format
      */
      void IvToStr(byte* iv, size_t vsize, std::string& out)
      {
         out.clear();
         CryptoPP::StringSource(iv, vsize, true,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(out)));
      }

      /*
      @brief encrypts files using AES

      @param inFile input file to be encrypted
      @param outFile file after encryption
      @param key the key used to encrypt
      @param ksize size of the key
      @param iv IV used in encryption
      @param vsize size of IV
      @param errMsg Error message to output

      @return bool for successful or failure
      */
      bool EncryptFile(std::ifstream& inFile,
         std::ofstream& outFile,
         const byte* key, size_t ksize,
         const byte* iv, size_t vsize,
         std::string& errMsg)
      {
         try {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;

            e.SetKeyWithIV(key, ksize, iv, vsize);
            CryptoPP::FileSource(inFile, true,
               new CryptoPP::StreamTransformationFilter(e, new CryptoPP::FileSink(outFile)));
            inFile.close();
            outFile.close();
         }
         catch (CryptoPP::Exception& e) {
            errMsg = e.GetWhat();
            return false;
         }
         return true;
      }

      /*
      @brief decrypts files using AES

      @param inFile input file to be decrypted
      @param outFile file after decryption
      @param key the key used to decrypt
      @param ksize size of the key
      @param iv IV used in decryption
      @param vsize size of IV
      @param errMsg Error Message to output

      @return bool for successful or failure
      */
      bool DecryptFile(std::ifstream & inFile,
         std::ofstream & outFile,
         const byte* key, size_t ksize,
         const byte* iv, size_t vsize,
         std::string & errMsg)
      {
         try {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
            d.SetKeyWithIV(key, ksize, iv, vsize);
            CryptoPP::FileSource(inFile, true,
               new CryptoPP::StreamTransformationFilter(d, new CryptoPP::FileSink(outFile)));
            inFile.close();
            outFile.close();
         }
         catch (CryptoPP::Exception& e) {
            errMsg = e.GetWhat();
            return false;
         }
         return true;
      }

   }
}




