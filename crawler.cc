
#include <stdio.h>
#include <gzstream.h>
#include <stdlib.h>
#include <string>
#include <signal.h>
#include "dns_db.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ares.h>

bool doexit = false;

void sigterm(int) {
	std::cerr << "Exiting" << std::endl;
	doexit = true;
}

static void callback(void *arg, int status, int timeouts, struct hostent *host);
const char * dns_servers[4] = { "209.244.0.3", "209.244.0.4", "8.8.8.8", "8.8.4.4" };
struct in_addr dns_servers_addr[4];

DNS_DB * db;
int inflight = 0;
#define MAX_INFLIGHT 1000

int main(int argc, char ** argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s dbpath\n", argv[0]);
		exit(0);
	}

	signal(SIGTERM, sigterm);
	signal(SIGINT,  sigterm);

	std::string pathdb  = std::string(argv[1]);
	db = new DNS_DB(pathdb);

	ares_channel channel;
	int status, addr_family = AF_INET;
	fd_set read_fds, write_fds;
	struct timeval *tvp, tv;

	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
		return 1;
	}

	addr_family = AF_INET;
	struct ares_options a_opt;
	memset(&a_opt,0,sizeof(a_opt));
	a_opt.tries = 1;
	a_opt.nservers = sizeof(dns_servers)/sizeof(dns_servers[0]);
	a_opt.servers = &dns_servers_addr[0];
	for (int i = 0; i < a_opt.nservers; i++)
		inet_aton(dns_servers[i], &dns_servers_addr[i]);

	status = ares_init_options(&channel, &a_opt, ARES_OPT_TRIES | ARES_OPT_SERVERS | ARES_OPT_ROTATE);
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "ares_init: %s\n", ares_strerror(status));
		return 1;
	}

	DNS_DB::DomainIterator it = db->getDomainIterator();
	while (!doexit) {
		while (!it.end()) {
			std::string dom = it.getDomain();
			char * arg = (char*) malloc(dom.size()+1);
			memcpy(arg, dom.c_str(), dom.size()+1);
			ares_gethostbyname(channel, dom.c_str(), addr_family, callback, (void*)arg);
			inflight++;
			it.next();
			if (inflight >= MAX_INFLIGHT)
		        break;
		}
		
		/* Wait for queries to complete. */
		do {
			FD_ZERO(&read_fds);
			FD_ZERO(&write_fds);
			int nfds = ares_fds(channel, &read_fds, &write_fds);
			tvp = ares_timeout(channel, NULL, &tv);
			if (nfds > 0)
				select(nfds, &read_fds, &write_fds, NULL, tvp);
			ares_process(channel, &read_fds, &write_fds);
		} while(inflight >= MAX_INFLIGHT || it.end());
	}

	ares_destroy(channel);
	ares_library_cleanup();
}


static void callback(void *arg, int status, int timeouts, struct hostent *host) {
	inflight--;
	std::string domarg = std::string((char*)arg);
	free(arg);

	if (status == ARES_SUCCESS) {
		std::cout << domarg << " " << host->h_name << std::endl;

		std::string domain = domarg;
		if (host->h_addr == 0) return;
		unsigned int ip = *(unsigned int*)host->h_addr;
		if (db->hasDomain(domain)) {
			DNS_DB::DomainIterator it = db->getDomainIterator(domain);
			std::vector <IPv4_Record> r = it.getIpsv4();
			IPv4_Record rec, oldrec;
			rec.first_seen = time(0);
			rec.last_seen = time(0);
			rec.ip = ip;

			bool replace = false;
			for (unsigned int i = 0; i < r.size(); i++) {
				if (r[i].ip == ip) {
					rec.first_seen = r[i].first_seen;
					oldrec = r[i];
					replace = true;
					break;
				}
			}
			if (replace)
				db->replaceIpv4(domain, oldrec, rec);
			else
				it.addIpv4(rec);
		}
	}
}


