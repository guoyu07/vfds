CC=gcc
CXX=g++
INC+= -I../lib
LIB+=-lpthread -lssl  -L../lib -ltools
CFLAGS+= -g -O2 -pipe -Wall -fno-strict-aliasing -D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64#-z defs
TARGET=ssl_client
ALL:$(TARGET)

OBJ=ssl_client.o

$(TARGET):$(OBJ)
	$(CC)	$(CFLAGS) -o $@ $^ $(LIB)
%.o: %.cpp
	$(CXX)  $(CFLAGS) $(INC) -c -o $@ $< 	 
%.o: %.c
	$(CC)  $(CFLAGS) $(INC) -c -o $@ $< 	 
clean:
	rm -f *.o ssl_client
	rm -f $(TARGET) 	
