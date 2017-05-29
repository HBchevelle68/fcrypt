/*
   @Author - Anthony Portante
*/
#include "RSA.h"

namespace FCrypt {
   namespace RSA {

      /*
      @brief RSA key pair generation. Key size determined by
      @param keysize

      @param priv reference to the private key to be generated
      @param pub reference to the public key to be generated
      @param keysize size for private and public keys.

      Possible values are: {(WEAK:1024), (NORM:2048),
      (STRONG:3072), (Y_THO:4096), and (PLS_KYS:8192)
      */
      void GenKeyPair(CryptoPP::RSA::PrivateKey& priv, CryptoPP::RSA::PublicKey& pub, const size_t keySize)
      {
         CryptoPP::AutoSeededRandomPool prng;
         CryptoPP::InvertibleRSAFunction parameters;

         parameters.GenerateRandomWithKeySize(prng, keySize);
         CryptoPP::RSA::PrivateKey privateKey(parameters);
         CryptoPP::RSA::PublicKey publicKey(parameters);

         priv = std::move(privateKey);
         pub = std::move(publicKey);
      }

      /*
      @brief Function encrypts plaintext using RSA public key.
      Outputs to ciphertext reference variable

      @param pub reference to the public key used to encrypt the plaintext
      @param plain reference to the plaintext being encrypted
      @param cipher refernce to the ciphertext being generated
      */
      void EncryptString(CryptoPP::RSA::PublicKey& pub, std::string& plain, std::string& cipher)
      {
         CryptoPP::AutoSeededRandomPool prng;
         CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pub);
         CryptoPP::StringSource(plain, true,
            new CryptoPP::PK_EncryptorFilter(prng, encryptor, new CryptoPP::StringSink(cipher)));
      }

      /*
      @brief Function decrypts ciphertext using RSA private key.
      Outputs to plaintext reference variable

      @param priv reference to the private key used to decrypt the cipher text
      @param cipher reference to the ciphertext being decrypted
      @param plain reference to the resulting plaintext after decryption
      */
      void DecryptString(CryptoPP::RSA::PrivateKey& priv, std::string& cipher, std::string& plain)
      {
         CryptoPP::AutoSeededRandomPool prng;
         CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(priv);
         CryptoPP::StringSource(cipher, true,
            new CryptoPP::PK_DecryptorFilter(prng, decryptor, new CryptoPP::StringSink(plain)));
      }

   }

}


