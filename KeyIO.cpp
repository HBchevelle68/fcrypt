#include "KeyIO.h"


namespace FCrypt {
   namespace KeyIO {

      /*
      @brief takes in byte(unsigned char) array and uses 
             Crypto++ library to filter and pass to 
             stdout

      @param barray the byte array to print 
      @param ksize the size of the byte array
      */
      void printBytes(byte * barray, size_t asize) {
         CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
         CryptoPP::ByteQueue bq;
         bq.Put(barray, asize);
         bq.CopyTo(encoder);
         encoder.MessageEnd();
         std::cout << std::endl;
      }
      /*
      @brief Encrypts the byte array containing a key

      @param key byte array of key that PERFORMS the encryption
      @param ksize the size of the key in bytes
      @param iv byte array containing iv for key  
      @param vsize the size of the iv in bytes
      @param keyToEnc the byte array containing the key
             that will GET ENCRYPTED
      @param toEncSize the size of keyToEnc
      @param out byte array containing the encrypted key
      */
      //WARNING!!! @param out MUST BE SIZE 48!!!!
      void EncryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* keyToEnc, const size_t toEncSize, byte* out){
         //make encryptor
         CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
         enc.SetKeyWithIV(key, ksize, iv, vsize);

         //move bytes of ACTUAL AES KEY to ByteQueue
		   CryptoPP::ByteQueue pKey, eKey;
         pKey.Put(keyToEnc, toEncSize);

         CryptoPP::StreamTransformationFilter f1(enc, new CryptoPP::Redirector(eKey));
         pKey.CopyTo(f1);
         f1.MessageEnd();
         //at this point the ENCRYPTED key is in ByteQueue eKey

		 eKey.Get( out, eKey.CurrentSize() );
      }
      /*
      @brief Encrypts the byte array containing a key

      @param key byte array of key that PERFORMS the decryption
      @param ksize the size of the key in bytes
      @param iv byte array containing iv for key  
      @param vsize the size of the iv in bytes
      @param keyToEnc the byte array containing the key
             that will GET DECRYPTED
      @param toEncSize the size of keyToEnc
      @param out byte array containing the Decrypted key
      */
      void DecryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* toDecrypt, const size_t toDecSize, byte* decrypted){
         //move byte array to decrypt into ByteQueue
		   CryptoPP::ByteQueue cipher, recover;
         cipher.Put(toDecrypt, toDecSize);

         //make decryptor
         CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
         dec.SetKeyWithIV(key, ksize, iv, vsize);

         CryptoPP::StreamTransformationFilter f2(dec, new CryptoPP::Redirector(recover));
         cipher.CopyTo(f2);
         f2.MessageEnd();
         //at this point the DECRYPTED key is in ByteQueue recover
         recover.Get(decrypted, recover.CurrentSize());
      }
      /*
      @brief Writes string to file containing key length,
             key, and IV.

      @param ofName ref to name of out file
      @param kSize the size of the key in bytes
      @param kStr string version of AES key 
      @param ivStr string version of IV
      */
      void WriteToFile(std::string& ofName, size_t kSize, std::string& kStr, std::string& ivStr){
         std::ofstream outF(ofName, std::ios::app);
         outF << "\n" << "$" << kSize << "$" << kStr << "$" << ivStr << "$" << std::endl;
         outF.close();
      }
      /*
      @brief Takes in key and IV in byte form and trasnforms them 
             into strings for writing to a file. Then calls
             WriteToFile to write transformed strings

      @param key byte array of key
      @param kSize size of key in bytes
      @param iv byte array of IV
      @param vsize size of iv in bytes
      @param ofName name of file to write to
      */
      void StoreToFile(byte* key, size_t ksize, byte* iv, size_t vsize, std::string& ofName){
         std::string kStr, ivStr;
         kStr.clear();
         ivStr.clear();
         CryptoPP::StringSource ss0(key, ksize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(kStr)));
         CryptoPP::StringSource ss1(iv, vsize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ivStr)));
         WriteToFile(ofName, ksize, kStr, ivStr);
      }
      /*
      @brief Extracts the string appended to encrypted file 
             by WriteToFile function.  

      @param ofName
      @param kSize size of key in byte

      @return returns int of size of original file
      */
      int ExtractKIV(std::string& ifName, std::string& extracted){
         std::ifstream inF(ifName, std::ios::ate); //open and go to EOF
         int pos, len = inF.tellg(); 
         std::string eStr;
         char curChar = '\0';
         for(int i = len-2; i > 0; i--){
            inF.seekg(i);
            curChar = inF.get();
            if(curChar == '\n' || curChar == '\r'){
               pos = i;
               break;
            }
         }
         //std::cout << len << " " << pos << std::endl; //DEBUG
         std::getline(inF, extracted);
         //std::cout << extracted << std::endl; //DEBUG
         inF.close();
         return pos;
      }
      /*
      @brief strips extracted string then calls conversion
             function to convert from string to byte array

      @param toStrip string to strip
      @param key byte array to hold key after conversion
      @param ksize size of key
      @param iv byte array to hold IV after conversion
      @return returns int of size of original file
      */
      void Strip(std::string& toStrip, byte* key, size_t ksize, byte* iv){
         size_t pos = 0;
         short i = 0;
         std::string KIV[4], token, delim = "$";
         while ((pos = toStrip.find(delim)) != std::string::npos) {
             KIV[i++] = toStrip.substr(0, pos);
             //KIV[i++] = token;
             //std::cout << token << std::endl;
             toStrip.erase(0, pos + delim.length());
         }
         stob(KIV[2], key, ksize);
         stob(KIV[3], iv, IVSIZE);
      }
      /*
      @brief transforms strings to byte arrays

      @param encoded string to convert
      @param barray byte array to hold data after conversion
      @param bsize size of barray
      */
      void stob(std::string& encoded, byte* barray, size_t bsize){         
         CryptoPP::HexDecoder decoder;
         decoder.Put((byte*)encoded.data(), encoded.size());
         decoder.MessageEnd();
         decoder.Get(barray, bsize);
         //printBytes(barray, len);
      }

   }

}

