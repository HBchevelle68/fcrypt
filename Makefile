OBJS = fcrypt.o AES.o Hash.o KeyIO.o 
CC = g++
CFLAGS = -c -Wall -std=c++11
LFLAGS = -lcryptopp  

all: $(OBJS)
	$(CC) $(OBJS) $(LFLAGS) -o fcrypt

fcrypt.o: fcrypt.cpp AES.h Hash.h KeyIO.h
	$(CC) $(CFLAGS) fcrypt.cpp

AES.o: AES.h AES.cpp 
	$(CC) $(CFLAGS) AES.cpp 

Hash.o: Hash.h Hash.cpp
	$(CC) $(CFLAGS) Hash.cpp 

KeyIO.o: KeyIO.h KeyIO.cpp AES.h Hash.h
	$(CC) $(CFLAGS) KeyIO.cpp 

clean:
	rm *.o fcrypt
