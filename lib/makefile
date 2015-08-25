#lib makefile
OBJ=log.o  util_ip.o myconfig.o util_hex.o util_misc.o util_str.o util_http.o common.o myepoll.o protocol.o base64.o CSmtp.o c_mail.o
LIBNAME=libtools
STLIBSUFFIX=a
STLIBNAME=$(LIBNAME).$(STLIBSUFFIX)

CC:=$(shell sh -c 'type $(CC) >/dev/null 2>/dev/null && echo $(CC) || echo gcc')
CXX=g++
STLIB_MAKE_CMD=ar rcs $(STLIBNAME)

INC+=
LIB+= -lpthread -lssl -ldl -lrt -lstdc++ -rdynamic -lz
CFLAGS+= -g -O2 -pipe -Wall -fno-strict-aliasing -D_GNU_SOURCE -D_REENTRANT -DLINUX -Wl,-Bdynamic -lssl -fPIC

ALL: $(STLIBNAME) $(PROGNAME) 

$(STLIBNAME): $(OBJ)
	$(STLIB_MAKE_CMD) $(OBJ)

%.o: %.cpp
	$(CXX) $(LIB) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(STLIBNAME) *.o
