
#ifndef COMMAND__H__
#define COMMAND__H__

#include "record.h"

class Command {
public:
	enum Type { 
		// Read
		QueryDomain, 
		GetIterator, 
		IteratorNext, IteratorPrev, IteratorValue,
		// Write
		AddDomain, DeleteDomain, UpdateDomain
	};

	static Command queryDomain();
	static Command getIterator();
	static Command iteratorNext();
	static Command iteratorPrev();
	static Command iteratorValue();
	static Command addDomain();
	static Command deleteDomain();
	static Command updateDomain();

private:
	unsigned int iterator;

	std::string domain;
	std::vector <IPv4_Record> records;

};

#endif

