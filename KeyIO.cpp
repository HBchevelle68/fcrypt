#include "KeyIO.h"

namespace FCrypt {
   namespace KeyIO {

      //WARNING!!! OUT MUST BE SIZE 48!!!!
      void EncryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* keyToEnc, const size_t ktoEncSize, byte* out)
      {
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

      void DecryptKey(const byte* key, const size_t ksize, const byte* iv, const size_t vsize, byte* toDecrypt, const size_t toDecSize, byte* decrypted)
      {
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

      void KIVbtos(byte* key, size_t ksize, byte* iv, size_t vsize, std::string& kStr, std::string& ivStr){
         
         kStr.clear();
         ivStr.clear();
         CryptoPP::StringSource ss0(key, ksize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(kStr)));
         CryptoPP::StringSource ss1(key, ksize, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ivStr)));

      }

   }

}

