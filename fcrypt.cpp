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
#include <stdlib.h>

#include "AES.h"
#include "RSA.h"
#include "KeyIO.h"

void usage();

int main(int argc, char* argv[]){
	
	if(argc < 5){
		usage();
		return 0;
	}

	if(argv[2][0] == '-' && argv[2][1] == 'e'){

		if(argv[3][0] == '-' && argv[3][1] == 'p' && argv[4] != NULL){

			std::ifstream fte(argv[1]);
			if(fte.is_open()){
				//Key IV generation
		   		byte key[AES128];
		  		byte iv[IVSIZE];
		  		FCrypt::AES::GenKeyIv(key, AES128, iv, IVSIZE);
		   		 
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
		   			std::remove(argv[1]);
		   		}
		   		//Write Key IV to file
		   		//TO-DO, write encrypted version of key	
				FCrypt::KeyIO::StoreToFile(key, AES128, iv, IVSIZE, encF);
			}
			else {
				std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
			}
		}
		else usage();

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

			#ifdef __linux__
				realpath(argv[1], fpath);
				truncate(fpath, nsize);
			#endif

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
  std::cout << "Usage: ./fcrypt [FILE] [ACTION] [-p] [PASSWORD]" << std::endl;

  std::cout << "\nActions:" << std::endl;
  std::cout << std::setw(10) << std::left << "  -e"  << "Encrypt file using AES" << std::endl;
  std::cout << std::setw(10) << std::left << "  -d"  << "Decrypt file previously encrypted by fcrypt" << std::endl;
  std::cout << "\nPassword:" << std::endl;
  std::cout << std::setw(10) << std::left << "  -p"  << "Password for file" << std::endl;
}
