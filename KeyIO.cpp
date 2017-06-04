/*
   @Author - Anthony Portante
*/
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
      @brief Takes in key and IV in byte form and trasnforms them 
             into strings for writing to a file. Then calls
             WriteToFile to write transformed strings

      @param key byte array of key
      @param kSize size of key in bytes
      @param iv byte array of IV
      @param vsize size of iv in bytes
      @param ofName name of file to write to
      */
      void StoreToFile(size_t ksize, int pos, byte* iv, std::string& hash, std::string& salt, std::string& ofName){
         std::string ivStr;
         CryptoPP::StringSource ss(iv, IVSIZE, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ivStr)));
         std::ofstream outF(ofName, std::ios::app);
         outF << "\n" << "$" << ksize << "$" << pos << "$" << ivStr << "$" << hash << "$" << salt << "$" <<std::endl;
         outF.close();
      }
      /*
      @brief Extracts the string appended to encrypted file 
             by WriteToFile function.  

      @param ofName
      @param kSize size of key in byte

      @return returns int of size of original file
      */
      int Extract(std::string& ifName, std::string& extracted){
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
         std::getline(inF, extracted);
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
      bool Strip(std::string& toStrip, std::string& pwd, byte* key, size_t ksize, byte* iv, std::string& err){
         size_t index = 0;
         short i = 0;
         std::string stripped[7], token, delim = "$";
         while ((index = toStrip.find(delim)) != std::string::npos) {
             stripped[i++] = toStrip.substr(0, index);
             toStrip.erase(0, index + delim.length());
         }
         std::string temp;
         FCrypt::Hash::SHA_512(pwd, temp, stripped[5]);
         if(temp.compare(stripped[4])){
            err = "Pasword Mismatch\n";
            return false;
         }
         //Convert IV from String to byte
         stob(stripped[3], iv, IVSIZE);
         int pos = stoi(stripped[2]);
         //Regenerate key
         FCrypt::AES::UserGen(pwd, stripped[5], stripped[4], key, ksize, iv, pos);
         return true;
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
      }
      /*
      @brief Write over array containing key
      
      @param key byte array pointer to key
      @param size size of key
      */
      void KeyOverwrite(byte* key, size_t size){
         for(int i = 0; i<100; i++){
            for(int j = 0; j<(int)size; j++){
               key[j] = (unsigned char)FCrypt::AES::GenRand(0,127);
            }
         } 
      }
   }

}

