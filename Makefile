OBJS = fcrypt.o AES.o RSA.o KeyIO.o 
CC = g++
CFLAGS = -Wall -c -std=c++11
LFLAGS = -lcryptopp  

all: $(OBJS)
	$(CC) $(OBJS) $(LFLAGS) -o fcrypt

fcrypt.o: fcrypt.cpp AES.h RSA.h KeyIO.h
	$(CC) $(CFLAGS) fcrypt.cpp

AES.o: AES.h AES.cpp 
	$(CC) $(CFLAGS) AES.cpp 

RSA.o: RSA.h RSA.cpp
	$(CC) $(CFLAGS) RSA.cpp 

KeyIO.o: KeyIO.h KeyIO.cpp AES.h
	$(CC) $(CFLAGS) KeyIO.cpp 

clean:
	rm *.o fcrypt
