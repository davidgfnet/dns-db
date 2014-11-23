
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include "dns_db.h"


DNS_DB::DNS_DB(const std::string & path) : blockmgr(this), index(this) {
	db_path = path;
	
	// Read index
	index.unserialize(path + "/index");
}

DNS_DB::~DNS_DB() {
	// Read index
	index.serialize(db_path + "/index");
}

std::string to_string(unsigned int n, int n_digits) {
	std::string r;
	while (n_digits-- > 0 || n > 0) {
		r = std::to_string(n%10) + r;
		n /= 10;
	}
	return r;
}

// DB check!
void DNS_DB::check() {
	// Do a full DB check. Check the index and then each block
	index.check();
}

DNS_DB::DnsBlock * DNS_DB::getNewBlock(int blockid) {
	// Generate path in a hierachical way, to prevent many files in a directory
	// This should be beneficial on most file systems
	std::string filename = to_string(blockid,16);
	std::string dir1 = filename.substr(filename.size()-1,1) + "/";
	std::string dir2 = filename.substr(filename.size()-2,1) + "/";
	std::string blockfile = db_path + "/" + dir1 + dir2 + filename + ".blk";

	if (!FileMapper::getInstance().fileExists(blockfile)) {
		mkdir((db_path).c_str(),                           S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		mkdir((db_path + "/" + dir1).c_str(),              S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		mkdir((db_path + "/" + dir1 + "/" + dir2).c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}

	return new DNS_DB::DnsBlock(blockfile, blockid);
}


DNS_DB::DomainIterator::DomainIterator(DNS_DB::DnsIndex * idx, DNS_DB * dbref) : it(idx->getIterator()), db(dbref) {}


