
CPP=g++

DEBUG=-DEXTRA_CHECK -O0
RELEASE=-DNDEBUG -O3

PG=#-pg
#OPTS=-O1  -DFAST_SEARCH
#OPTS=$(RELEASE)  -DFAST_SEARCH
OPTS=-O3   -DFAST_SEARCH  -DEXTRA_CHECK
OBJS = dns_db.o dns_index.o dns_block.o util.o file_mapper.o bitmap.o block_manager.o
CFLAGS= -ggdb $(PG)  $(OPTS) #-Wall
CPPFLAGS=-std=c++11 $(CFLAGS)

all:	$(OBJS)
	$(CPP) $(CPPFLAGS) $(PG) -o dns $(OBJS) main.cc ext/gzstream.cc  -I ext/ -lz -ggdb

crawler:	$(OBJS)
	$(CPP) $(CPPFLAGS) $(PG) -o crawler $(OBJS) crawler.cc ext/gzstream.cc  -I ext/ -lz -ggdb -lcares

%.o:	%.cc
	$(CPP) $(CPPFLAGS) -c $<

clean:
	rm -f $(OBJS) dns

