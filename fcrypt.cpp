/*
   @Author - Anthony Portante
*/
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
#include "KeyIO.h"
#include "Hash.h"

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
				size_t size; 
				if(argv[2][2] == '1'){
					std::cout << "Encrypting " << argv[1] << " with AES-128" << std::endl;
		   			size = AES128;
				}else if(argv[2][2] == '2'){
					std::cout << "Encrypting " << argv[1] << " with AES-192" << std::endl;
		   			size = AES192;

				}else if(argv[2][2] == '3'){
					std::cout << "Encrypting " << argv[1] << " with AES-256" << std::endl;
		   			size = AES256;
				}else{
					fte.close();
					usage();
					return 0;
				}
				byte key[(const size_t)size];
				byte iv[IVSIZE];
		  		int pos = 0;
		  		std::string salt, hash, pwd = argv[4];
		  		memset(key,0,sizeof(key));
				memset(iv,0,sizeof(iv));
		  		// gen key, iv, hash, salt, position
		  		FCrypt::AES::UserGen(pwd, salt, hash, key, sizeof(key), iv, pos);
				std::string err, old(argv[1]), encF(argv[1]);
		   		std::ofstream efile(encF.append(".crypt"));
		   		if(!FCrypt::AES::EncryptFile(fte, efile, key, sizeof(key), iv, IVSIZE, err)){
		   			std::cout << "Encryption Error: " << err << std::endl;
		   			fte.close();
		   			efile.close();
		   			return 1;
		   		} 
		   		else {
		   			std::remove(argv[1]);
		   		}
		   		//Write Key IV to file
				FCrypt::KeyIO::StoreToFile(sizeof(key), pos, iv, hash, salt, encF);
				FCrypt::KeyIO::KeyOverwrite(key, sizeof(key));
			}
			else {
				std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
			}
		}
		else usage();
	}
	else if(argv[2][0] == '-' && argv[2][1] == 'd'){ //Decyption	

		if(argv[3][0] == '-' && argv[3][1] == 'p' && argv[4] != NULL){

			std::ifstream efile(argv[1]);
			if(efile){
				std::cout << "Decrypting " << argv[1] << std::endl;
				char fpath[200];
				std::string err, extracted, pwd = argv[4], inputFile = argv[1];

				int nsize = FCrypt::KeyIO::Extract(inputFile, extracted);
				int klen = std::stoi(extracted.substr(1,2));
				byte key[klen], iv2[IVSIZE];
				if(!FCrypt::KeyIO::Strip(extracted, pwd, key, sizeof(key), iv2, err)){
					std::cout << err << std::endl;
					efile.close();
					return 1;
				}

				#ifdef __linux__
					realpath(argv[1], fpath);
					truncate(fpath, nsize);
				#endif

				std::string origName = inputFile.substr(0,inputFile.find(".crypt"));
				std::ofstream dfile(origName);
				if(!FCrypt::AES::DecryptFile(efile, dfile, key, sizeof(key), iv2, IVSIZE, err)){
		   			std::cout << "Decryption Error: " << err << std::endl;
		   			efile.close();
		   			dfile.close();
		   			return 1;
		   		} 
		   		else {
		   			std::remove(argv[1]);
		   		}
		   		FCrypt::KeyIO::KeyOverwrite(key, sizeof(key));			
			}
			else {
				std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
			}
		}
		else usage();	
	}
	else{
		usage();
	}

	return 0;
}

void usage() {
	std::cout << "Usage: ./fcrypt [FILE] [ACTION] [-p] [PASSWORD]" << std::endl;
	std::cout << "\nActions:" << std::endl;
	std::cout << std::setw(10) << std::left << "  -e"  << "Encrypt file using AES" << std::endl;
	std::cout << std::setw(10) << std::left << "  -d"  << "Decrypt file previously encrypted by fcrypt" << std::endl;
	std::cout << "\nPassword:" << std::endl;
	std::cout << std::setw(10) << std::left << "  -p"  << "Password for file" << std::endl;
}
