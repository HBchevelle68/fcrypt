#include <cstdio>

#include "AES.h"
#include "RSA.h"





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
   		std::ofstream outF(temp.append(".crypt"), std::ios::out | std::ios::app);
   	
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
		std::ofstream outF2(temp, std::ios::app);
   		outF2 << "\n" << "$" << key << "$" << iv << "$" << std::endl;
   		outF2.close();	

		

	}
	else {
		std::cout << "Error: no file " << argv[1] << " found\n" << std::endl;
	}


	return 0;
}