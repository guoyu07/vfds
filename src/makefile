NS=test_master
CC=gcc
CXX=g++
INC+= -I../lib
LIB+= -lpthread -ldl -lrt -lssl -rdynamic -L../lib -ltools
CFLAGS+= -g -O2 -pipe -Wall -fno-strict-aliasing -D_GNU_SOURCE -D_REENTRANT -D_NS_=\"$(NS)\"
TARGET=$(NS)
ALL:$(TARGET)

OBJ= main.o	\
	fdinfo.o	\
	daemon.o \
	task.o	\
	thread.o	\
	version.o	\
	watchdog.o	\
	mybuff.o	\
	so.o 		\
	init.o		\
		
$(TARGET):$(OBJ)
	$(CC)	$(CFLAGS) -o $@ $^ $(LIB)
#	install $(TARGET) ../bin
%.o: %.cpp
	$(CXX)  $(CFLAGS) $(INC) -c -o $@ $< 	 
%.o: %.c
	$(CC)  $(CFLAGS) $(INC) -c -o $@ $< 	 
clean:
	rm -f $(OBJ)
	rm -f $(TARGET) 	
