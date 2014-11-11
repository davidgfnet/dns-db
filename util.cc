
#include <string>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "dns_db.h"


// Domain is somewhat compressed. Remove the .something and concat a character
const char * tld_domains[] = {
	"",
	"com", "org", "net", "int", "edu", "gov", "mil", 
	"biz", "info",
	"at", "ca", "de", "es", "ru", "us", "fr"
};

bool domain2idom(const char * domain, char * intdom) {
	const char * dot = strstr(domain,".");
	if (dot == NULL) return false;

	uintptr_t length = ((uintptr_t)dot) - ((uintptr_t)domain);
	if (length > 34) return false;

	int tldn = -1;
	for (unsigned int i = 0; i < sizeof(tld_domains)/sizeof(tld_domains[0]); i++) {
		if (strcmp(dot+1, tld_domains[i]) == 0) {
			tldn = i;
			break;
		}
	}

	if (tldn < 0) return false;

	memset(intdom, 0, MAX_DNS_SIZE);
	memcpy(intdom, domain, length);
	intdom[length] = (char)tldn;
	return true;
}

void idom2domain(const char * intdom, char * domain) {
	int length = MAX_DNS_SIZE;
	if (intdom[MAX_DNS_SIZE-1] == 0)
		length = strlen(intdom);

	int ext = (int)intdom[length-1];
	memcpy(domain, intdom, length-1);
	domain[length-1] = '.';
	domain[length] = 0;
	strcat(domain, tld_domains[ext]);
}


