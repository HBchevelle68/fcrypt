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
#include <iomanip>

#include "AES.h"
#include "RSA.h"
#include "KeyIO.h"

void usage();

int main(int argc, char* argv[]){
	
	if(argc < 3){
		usage();
		return 0;
	}

	if(argv[2][0] == '-' && argv[2][1] == 'e'){

		std::ifstream fte(argv[1]);
		if(fte.is_open()){
			//Key IV generation
	   		byte key[AES128];
	  		byte iv[IVSIZE];
	  		FCrypt::AES::GenKeyIv(key, AES128, iv, IVSIZE);

	  		//	DEBUG
	  		/*
	  		std::string k = "";
	  		std::string v = "";
	  		FCrypt::AES::KeyToStr(key, AES128, k);
	  		FCrypt::AES::IvToStr(iv, IVSIZE, v);
	  		std::cout << "Key: " << k << std::endl; 
	   		std::cout << "IV: " << v << std::endl;
	   		*/
	   		//	END DEBUG
	   		 
			std::string err, encF(argv[1]);
	   		std::ofstream efile(encF.append(".crypt"));
	   	
	   		if(!FCrypt::AES::EncryptFile(fte, efile, key, AES128, iv, IVSIZE, err)){
	   			std::cout << "Encryption Error: " << err << std::endl;
	   			fte.close();
	   			efile.close();
	   			return 1;
	   		} 
	   		else {
	   			fte.close();
	   			efile.close();
	   			std::cout << argv[1] << std::endl;
	   			std::remove(argv[1]);
	   		}
	   		//Write Key IV to file
	   		//TO-DO, write encrypted version of key	
			FCrypt::KeyIO::KIVtof(key, AES128, iv, IVSIZE, encF);
		}
		else {
			std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
		}

	}
	else if(argv[2][0] == '-' && argv[2][1] == 'd'){ //Decyption	
		std::ifstream efile(argv[1]);
		if(efile){
			char fpath[200];
			std::string err, extracted, inputFile(argv[1]);

			int nsize = FCrypt::KeyIO::ExtractKIV(inputFile, extracted);
			int klen = std::stoi(extracted.substr(1,2));
			byte key2[klen], iv2[IVSIZE];
			FCrypt::KeyIO::Strip(extracted, key2, klen, iv2);

			getcwd(fpath, 200);
			strcat(fpath, "/");
			strcat(fpath, inputFile.c_str());
			truncate(fpath, nsize);

			std::string origName = inputFile.substr(0,inputFile.find(".crypt"));
			std::ofstream dfile(origName);
			if(!FCrypt::AES::DecryptFile(efile, dfile, key2, AES128, iv2, IVSIZE, err)){
	   			std::cout << "Decryption Error: " << err << std::endl;
	   			dfile.close();
	   			efile.close();
	   			return 1;
	   		} 
	   		else {
	   			efile.close();
	   			dfile.close();
	   			std::remove(argv[1]);
	   		}			
		}
		else {
			std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
		}


	}
	else{
		usage();
	}

	return 0;
}

void usage()
{
  std::cout << "Usage: ./fcrypt [FILE] [ACTION]" << std::endl;

  std::cout << "\nActions:" << std::endl;
  std::cout << std::setw(10) << std::left << "  -e"  << "Encrypt file using AES" << std::endl;
  std::cout << std::setw(10) << std::left << "  -d"  << "Decrypt file previously encrypted by fcrypt" << std::endl;
}
