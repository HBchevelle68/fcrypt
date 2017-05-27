#ifdef _WIN32

      //TO-DO
      //Add windows libs
#include <Windows.h>

#endif

#ifdef __linux__

#include <unistd.h>
#include <sys/types.h>

#endif

#include <cstdio>

#include "AES.h"
#include "RSA.h"
#include "KeyIO.h"




int main(int argc, char* argv[]){
	

	if(argc < 2){
		std::cout << "Need an arg" << std::endl;
		exit(1);
	}

	std::ifstream fte(argv[1]);
	if(fte.is_open()){
		
		
		//Key IV generation
   		byte key[AES128];
  		byte iv[IVSIZE];
  		FCrypt::AES::GenKeyIv(key, AES128, iv, IVSIZE);

  		//DEBUG
  		std::string k = "";
  		std::string v = "";
  		FCrypt::AES::KeyToStr(key, AES128, k);
  		FCrypt::AES::IvToStr(iv, IVSIZE, v);
  		std::cout << "Key: " << k << std::endl; 
   		std::cout << "IV: " << v << std::endl;
   		// END DEBUG
		
		std::string err("");
   		std::string temp(argv[1]);
   		std::ofstream outF(temp.append(".crypt"));
   	
   		if(!FCrypt::AES::EncryptFile(fte, outF, key, AES128, iv, IVSIZE, err)){
   			std::cout << "Encryption Error: " << err << std::endl;
   			fte.close();
   			outF.close();
   			return 1;
   		} 
   		else {
   			fte.close();
   			outF.close();
   			std::cout << argv[1] << std::endl;
   			std::remove(argv[1]);
   		}
   		//Write Key IV to file
   		//TO-DO, write encrypted version of key
		
		FCrypt::KeyIO::KIVtof(key, AES128, iv, IVSIZE, temp);	//key iv to file


		//Decyption	
		std::string extracted;
		int nsize = FCrypt::KeyIO::ExtractKIV(temp, extracted); //extract key/iv from encrypted file
		int klen = std::stoi(extracted.substr(1,2));
		byte key2[klen];
		byte iv2[IVSIZE];
		FCrypt::KeyIO::Strip(extracted, key2, klen, iv2);
		FCrypt::KeyIO::printBytes(key2, klen);
		FCrypt::KeyIO::printBytes(iv2, IVSIZE);
		char fpath[200];
		getcwd(fpath, 200);
		strcat(fpath, "/");
		strcat(fpath, temp.c_str());
		std::string t = fpath;
		std::cout << t << std::endl;
		truncate(fpath, nsize);

		
		std::string temp2 = temp.substr(0,temp.find(".crypt"));
		std::ifstream efile(temp);
		std::ofstream dfile(temp2);
		if(!FCrypt::AES::DecryptFile(efile, dfile, key2, AES128, iv2, IVSIZE, err)){
   			std::cout << "Decryption Error: " << err << std::endl;
   			dfile.close();
   			outF.close();
   			return 1;
   		} 
   		else {
   			efile.close();
   			dfile.close();
   			std::remove(temp.c_str());
   		}
	}
	else {
		std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
	}


	return 0;
}