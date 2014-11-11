
CPP=g++

DEBUG=-DEXTRA_CHECK
RELEASE=-DNDEBUG

PG=#-pg
OPTS=-DFAST_SEARCH $(DEBUG) 
OBJS = dns_db.o dns_index.o dns_block.o util.o file_mapper.o bitmap.o block_manager.o
CFLAGS= -ggdb -O2 $(PG)  $(OPTS) #-Wall
CPPFLAGS=-std=c++11 $(CFLAGS)

all:	$(OBJS)
	$(CPP) $(CPPFLAGS) $(PG) -o dns $(OBJS) main.cc ext/gzstream.cc  -I ext/ -lz -ggdb

%.o:	%.cc
	$(CPP) $(CPPFLAGS) -c $<

clean:
	rm -f $(OBJS) dns

