
#include <stdio.h>
#include <gzstream.h>
#include <stdlib.h>
#include <string>
#include <signal.h>
#include "dns_db.h"


bool doexit = false;

void sigterm(int) {
	std::cerr << "Exiting" << std::endl;
	doexit = true;
}


int main(int argc, char ** argv) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s dbpath command (args...)\n", argv[0]);
		fprintf(stderr, " Commands:\n");
		fprintf(stderr, "  * add-domains file\n");
		fprintf(stderr, "  * crawl bw(kbps)\n");
		exit(0);
	}

	signal(SIGTERM, sigterm);
	signal(SIGINT,  sigterm);

	std::string pathdb  = std::string(argv[1]);
	std::string command = std::string(argv[2]);
	std::string arg0    = std::string(argv[3]);

	DNS_DB db(pathdb);

	std::vector <std::string> check;
	
	if (command == "add-domains") {
		igzstream fin (arg0.c_str());
		std::string domain;
		while (fin >> domain && !doexit) {
			DNS_DB::queryError r = db.addDomain(domain);
			#ifdef EXTRA_CHECK
			assert(r == DNS_DB::resOK || r == DNS_DB::resAlreadyExists || r == DNS_DB::resDomainTooLong);
			if (r == DNS_DB::resOK)
				check.push_back(domain);
			#endif
		}

		for (unsigned int i = 0; i < check.size(); i++)
			assert(db.hasDomain(check[i]));
	}
	else if (command == "list-domains") {
		DNS_DB::DomainIterator it = db.getDomainIterator();
		while (!it.end()) {
			it.next();
			std::cout << it.getDomain() << std::endl;
			std::vector <IPv4_Record> r = it.getIpsv4();
			for (int i = 0; i < r.size(); i++) {
				std::cout << r[i].ip << " " << r[i].first_seen << " " << r[i].last_seen <<  std::endl;
			}
		}
	}
	else if (command == "summary") {
		int r = db.getNumberRecords();
		int f = db.getNumberFreeRecords();
		std::cout << "Total records " << r << std::endl;
		std::cout << "Total free records " << f << std::endl;
		std::cout << "Storage efficiency " << double(100*r)/(r+f) << std::endl;
		db.check();
	}
	else if (command == "crawl") {
		
	}
}



