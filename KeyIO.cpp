#include "KeyIO.h"


namespace FCrypt {
   namespace KeyIO {

      void printBytes(byte * barray, size_t barraySize) {
         CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
         CryptoPP::ByteQueue bq;
         bq.Put(barray, barraySize);
         bq.CopyTo(encoder);
         encoder.MessageEnd();
         std::cout << std::endl;
      }

      //WARNING!!! OUT MUST BE SIZE 48!!!!
      void EncryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* keyToEnc, const size_t ktoEncSize, byte* out){
         //make encryptor
         CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
         enc.SetKeyWithIV(key, ksize, iv, vsize);

         //move bytes of ACTUAL AES KEY to ByteQueue
		   CryptoPP::ByteQueue pKey, eKey;
         pKey.Put(keyToEnc, ktoEncSize);

         CryptoPP::StreamTransformationFilter f1(enc, new CryptoPP::Redirector(eKey));
         pKey.CopyTo(f1);
         f1.MessageEnd();
         //at this point the ENCRYPTED key is in ByteQueue eKey

		 eKey.Get( out, eKey.CurrentSize() );
      }

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

      void WriteToFile(std::string& ofName, size_t encSize, std::string& kStr, std::string& ivStr){
         std::ofstream outF(ofName, std::ios::app);
         outF << "\n" << "$" << encSize << "$" << kStr << "$" << ivStr << "$" << std::endl;
         outF.close();
      }

      void KIVtof(byte* key, size_t ksize, byte* iv, size_t vsize, std::string& ofName){
         std::string kStr, ivStr;
         kStr.clear();
         ivStr.clear();
         CryptoPP::StringSource ss0(key, ksize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(kStr)));
         CryptoPP::StringSource ss1(iv, vsize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ivStr)));
         WriteToFile(ofName, ksize, kStr, ivStr);
      }

      int ExtractKIV(std::string& ofName, std::string& extracted){
         std::ifstream inF(ofName, std::ios::ate); //open and go to EOF
         int pos, len = inF.tellg(); 
         std::string eStr;
         char curChar = '\0';
         for(int i = len-2; i > 0; i--){
            inF.seekg(i);
            curChar = inF.get(); //get character
            if(curChar == '\n' || curChar == '\r'){
               pos = i;
               break;
            }
         }
         std::cout << len << " " << pos << std::endl; //DEBUG
         std::getline(inF, extracted);
         std::cout << extracted << std::endl; //DEBUG
         inF.close();
         return pos;
      }

      void Strip(std::string& toStrip, byte* key, size_t ksize, byte* iv){
         size_t pos = 0;
         short i = 0;
         std::string KIV[4], token, delim = "$";
         while ((pos = toStrip.find(delim)) != std::string::npos) {
             token = toStrip.substr(0, pos);
             KIV[i++] = token;
             //std::cout << token << std::endl;
             toStrip.erase(0, pos + delim.length());
         }
         stob(KIV[2], key, ksize);
         stob(KIV[3], iv, IVSIZE);

      }
      void stob(std::string& encoded, byte* barray, size_t len){         
         CryptoPP::HexDecoder decoder;
         decoder.Put((byte*)encoded.data(), encoded.size());
         decoder.MessageEnd();
         decoder.Get(barray, len);
         //printBytes(barray, len);
      }

   }

}

