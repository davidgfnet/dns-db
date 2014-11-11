
#include <string>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "dns_db.h"

DNS_DB::Bitmap::Bitmap(int numBits) : bitm(numBits/(8*sizeof(unsigned int))) {}

int DNS_DB::Bitmap::getFirst(bool value) const {
	for (unsigned int idx = 0; idx < bitm.size(); idx++) {
		for (unsigned int off = 0; off < sizeof(unsigned int)*8; off++) {
			if (((bitm[idx] & (1<<off)) != 0) == value)
				return idx*sizeof(unsigned int)*8 + off;
		}
	}
	return -1;
}

int DNS_DB::Bitmap::getRight(unsigned int pos, bool set) const {
	unsigned int mask = set ? 0 : ~0;
	for (unsigned int idx = pos/(8*sizeof(unsigned int)); idx < bitm.size(); idx++) {
		if (bitm[idx] == mask) continue;
		for (unsigned int off = pos%(8*sizeof(unsigned int)); off < sizeof(unsigned int)*8; off++) {
			if (((bitm[idx] & (1<<off)) != 0) == set)
				return idx*sizeof(unsigned int)*8 + off;
		}
	}
	return -1;
}

int DNS_DB::Bitmap::bitCount() const {
	int ret = 0;
	for (unsigned int i = 0; i < bitm.size(); i++) {
		ret += __builtin_popcount(bitm[i]);
	}
	return ret;
}


