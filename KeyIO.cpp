#include "KeyIO.h"

namespace FCrypt {
   namespace KeyIO {

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

      void WriteToFile(std::string& ofName, std::string& kStr, std::string& ivStr){
         std::ofstream outF(ofName, std::ios::app);
         outF << "\n" << "$" << kStr << "$" << ivStr << "$" << std::endl;
         outF.close();
      }

      void KIVtof(byte* key, size_t ksize, byte* iv, size_t vsize, std::string& ofName){
         std::string kStr, ivStr;
         kStr.clear();
         ivStr.clear();
         CryptoPP::StringSource ss0(key, ksize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(kStr)));
         CryptoPP::StringSource ss1(key, ksize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ivStr)));
         WriteToFile(ofName, kStr, ivStr);
      }

      void ExtractKIV(std::string& ofName){
         std::ifstream inF(ofName, std::ios::ate); //open and go to EOF
         std::string eStr;
         int pos, len = inF.tellg(); 
         char curChar = '\0';
         for(int i = len-2; i > 0; i--){
            inF.seekg(i);
            curChar = inF.get(); //get character
            if(curChar == '\n' || curChar == '\r'){
               pos = i;
               break;
            }
            /*
            else if(curChar == '$'){
               tcount++;
            }

            if(tcount == 3){
               pos = --i;
               break;
            }
            */
         }
         std::cout << len << " " << pos << std::endl; 
         std::getline(inF, eStr);
         std::cout << eStr << std::endl;
         inF.close();
      }

   }

}

