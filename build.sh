#!/bin/bash

RCol='\e[0m'    # Text Reset

#High Intensity     Bold High Intensity 
IBla='\e[0;90m';    BIBla='\e[1;90m';
IRed='\e[0;91m';    BIRed='\e[1;91m';
IGre='\e[0;92m';    BIGre='\e[1;92m';
IYel='\e[0;93m';    BIYel='\e[1;93m';
IBlu='\e[0;94m';    BIBlu='\e[1;94m';
IPur='\e[0;95m';    BIPur='\e[1;95m';
ICya='\e[0;96m';    BICya='\e[1;96m';
IWhi='\e[0;97m';    BIWhi='\e[1;97m';

/bin/echo -e ${BIYel}[+] ${RCol}Checking for old files to clean-up
rm *.o 2> /dev/null; rm 1 2> /dev/null
if [ "$?" = "0" ]; then
	/bin/echo -e ${BIYel}[+] ${RCol}Cleaning workspace
	/bin/echo -e ${BIGre}[+] ${RCol}done
else
	/bin/echo -e ${BIYel}[+] ${RCol}No files need clean-up 
fi


/bin/echo -e ${BIYel}[+] ${RCol}Compiling Fcrypt
g++ -Wall fcrypt.cpp AES.cpp RSA.cpp KeyIO.cpp -o fcrypt -std=c++11 -lcryptopp  >1

/bin/echo -e ${BIYel}[+] ${RCol}Creating test.txt file
touch test.txt && echo This is a test > test.txt
 
/bin/echo -e ${BIGre}[+] ${RCol}done




