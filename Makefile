OBJS = fcrypt.o AES.o KeyIO.o 
CC = g++
CFLAGS = -c -Wall -std=c++11
LFLAGS = -lcryptopp  

all: $(OBJS)
	$(CC) $(OBJS) $(LFLAGS) -o fcrypt

fcrypt.o: fcrypt.cpp AES.h KeyIO.h
	$(CC) $(CFLAGS) fcrypt.cpp

AES.o: AES.h AES.cpp 
	$(CC) $(CFLAGS) AES.cpp 


KeyIO.o: KeyIO.h KeyIO.cpp AES.h
	$(CC) $(CFLAGS) KeyIO.cpp 

clean:
	rm *.o fcrypt
