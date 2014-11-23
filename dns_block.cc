
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "dns_db.h"

unsigned char DNS_DB::DnsBlock::flagUsed = 0x80;
unsigned char DNS_DB::DnsBlock::flagDomain = 0x40;
unsigned int DNS_DB::DnsBlock::blockSize = (1*1024*1024);
unsigned int DNS_DB::DnsBlock::numBlocks = (1*1024*1024 / 64);

#define EMPTY_FOUND     0
#define NO_EMPTY_SPOT  -1
#define ALREADY_EXISTS -2


/** Dns Block */

// Each block is 4MB. The block is subdivided in chunks of 64 bytes
// They have two possible format:
//  1 byte header, 35 byte domain,  2 * ip record (4 byte ts, 4 byte ts + 4 byte IP)
//  1 byte header, 3 byte padding,  5 * ip record (4 byte ts, 4 byte ts + 4 byte IP)
// Domains are sorted in lexicographical order, therefore to do a lookup we can use 
// dichotomic search on the 4MB block
// The 1 byte header bits mean:  7: used/not used 6:dns+ips/just ips
// We can extend it to be able to store IPv6 addrs

DNS_DB::DnsBlock::DnsBlock(const std::string & file, int blkid) {
	if (!FileMapper::getInstance().fileExists(file))
		FileMapper::getInstance().createFile(file, DNS_DB::DnsBlock::blockSize);
	
	void * ptr = FileMapper::getInstance().mapFile(file);

	this->blockptr = (InternalBlock *)ptr;
	this->endptr = &this->blockptr[numBlocks];
	this->blockid = blkid;
	this->bitmap.reset(new Bitmap(numBlocks));

	updateBM();

	assert(sizeof(InternalBlock) == 64);
}

DNS_DB::DnsBlock::~DnsBlock() {
	FileMapper::getInstance().unmap(blockptr);
}

DNS_DB::DnsBlock::DnsBlock(const DnsBlockPtr & other) {
	assert(0 && "This never happens!!\n");
}

void DNS_DB::DnsBlock::updateBM() {
	for (unsigned int i = 0; i < numBlocks; i++)
		bitmap->setBit(i, (blockptr[i].header & flagUsed) != 0);
}

void DNS_DB::DnsBlock::checkBM() {
	for (unsigned int i = 0; i < numBlocks; i++)
		assert( bitmap->getBit(i) == ((blockptr[i].header & flagUsed) != 0) );
}

DNS_DB::DnsBlock::InternalBlock * DNS_DB::DnsBlock::lookupDomain(const char * domain) const {
	// Pick the specified element
	DNS_DB::DnsBlock::InternalBlock * ptr = blockptr;
	
	while (ptr != endptr) {
		if (memcmp(domain, ptr->data.domain.domain, MAX_DNS_SIZE) == 0)
			return ptr;
		ptr++;
	}

	return 0;
}

// Lookups a domain and returns all its IPs (v4)
std::vector <IPv4_Record> DNS_DB::DnsBlock::getIpsv4(int p) const {
	std::vector <IPv4_Record> ret;
	const DNS_DB::DnsBlock::InternalBlock * ptr = &blockptr[p];
	if (ptr == 0)
		return ret;

	assert((ptr->header & DNS_DB::DnsBlock::flagDomain) != 0);
	assert((ptr->header & DNS_DB::DnsBlock::flagUsed) != 0);

	do {
		if (ptr->header & DNS_DB::DnsBlock::flagDomain) {
			for (int i = 0; i < 2; i++)
				if (ptr->data.domain.records[i].ip != 0)
					ret.push_back(ptr->data.domain.records[i]);
		}
		else {
			for (int i = 0; i < 5; i++)
				if (ptr->data.records.records[i].ip != 0)
					ret.push_back(ptr->data.records.records[i]);
		}
		ptr++;
	} while (ptr != endptr && !(ptr->header & DNS_DB::DnsBlock::flagDomain) && (ptr->header & DNS_DB::DnsBlock::flagUsed));

	return ret;
}

bool DNS_DB::DnsBlock::hasDomain(const char * domint) const {
	return lookupEmptyDomainSpot(domint,0) == ALREADY_EXISTS;
}

int DNS_DB::DnsBlock::lookupEmptyDomainSpot(const char * domain, int * pos) const {
	DNS_DB::DnsBlock::InternalBlock * ptr = blockptr;
	int last_empty = NO_EMPTY_SPOT;

	#ifdef FAST_SEARCH
	int first = 0, last = numBlocks-1;
	while (first != last) {
		// Look for a domain at a middle point
		int omiddle = (first+last)>>1;
		int middle = bitmap->getRight(omiddle, true);
		if (middle < 0) middle = last;
		while (middle <= last) {
			ptr = &blockptr[middle];
			if ((ptr->header & flagUsed) && (ptr->header & flagDomain))
				break;
			middle++;
		}
		// Discard this half, no domains here
		if (middle > last) {
			last = omiddle-1;
			if (last < first)
				last = first;
		}
		else {
			// Compare
			if ( less(ptr->data.domain.domain, domain) ) {
				first = omiddle+1;
			}
			else if ( greater(ptr->data.domain.domain, domain) ) {
				last = omiddle;
			}
			else {
				if (pos) *pos = first;
				return ALREADY_EXISTS;
			}
		}
		assert(last >= first);
	}
	ptr = &blockptr[first];
	if (!(ptr->header & flagUsed)) {
		if (pos) *pos = first;
		return EMPTY_FOUND; // Ended up on an empty block, must be this!
	}
	else {
		if ( greater(ptr->data.domain.domain, domain) ) {
			while (first >= 0) {
				if (!(blockptr[first].header & flagUsed)) {
					if (pos) *pos = first;
					return EMPTY_FOUND;
				}
				else if ((blockptr[first].header & flagDomain)) {
					if (eq(blockptr[first].data.domain.domain, domain)) {
						if (pos) *pos = first;
						return ALREADY_EXISTS;
					}
					else if (less(blockptr[first].data.domain.domain, domain)) {
						if (pos) *pos = first;
						return NO_EMPTY_SPOT;
					}
				}
				first--;
			}
			if (pos) *pos = 0;
			return NO_EMPTY_SPOT;
		}
		else if ( less(ptr->data.domain.domain, domain) ) {
			while (first < numBlocks) {
				if (!(blockptr[first].header & flagUsed)) {
					if (pos) *pos = first;
					return EMPTY_FOUND;
				}
				else if ((blockptr[first].header & flagDomain)) {
					if (eq(blockptr[first].data.domain.domain, domain)) {
						if (pos) *pos = first;
						return ALREADY_EXISTS;
					}
					else if (greater(blockptr[first].data.domain.domain, domain)) {
						if (pos) *pos = first;
						return NO_EMPTY_SPOT;
					}
				}
				first++;
			}
			if (pos) *pos = numBlocks;
			return NO_EMPTY_SPOT;
		}
		else {
			if (pos) *pos = first;
			return ALREADY_EXISTS;
		}
	}
	#else
	for (int i = 0; i < numBlocks; i++) {
		DNS_DB::DnsBlock::InternalBlock * ptr = &blockptr[i];
		// Mantain a pointer to the first empty block in the valid range
		if (!(ptr->header & flagUsed) && last_empty < 0)
			last_empty = i;

		// Stop after we find our spot
		if ((ptr->header & flagUsed) && (ptr->header & flagDomain)) {
			if ( less(ptr->data.domain.domain, domain) ) {
				last_empty = NO_EMPTY_SPOT;
			}
			else {
				// Found a domain which is bigger than us
				if (memcmp(domain, ptr->data.domain.domain, MAX_DNS_SIZE) == 0) {
					if (pos) *pos = i;
					return ALREADY_EXISTS;
				}
				break;
			}
		}
	}
	#endif

	// It can be either the empty slot to insert this one or null
	if (pos) *pos = last_empty >= 0 ? last_empty : 0;
	if (last_empty >= 0) return EMPTY_FOUND;
	return last_empty;
}

// Returns false if it cannot add the domain, usually because 
// of lack of space
DNS_DB::queryError DNS_DB::DnsBlock::addDomain(const char * domint) {
	int spot, res;
	res = lookupEmptyDomainSpot(domint, &spot);

	if (res == NO_EMPTY_SPOT) {
		// No spece between records or at the end of the block,
		// we need to do some relocs or split the chunk

		// Try to find a place again
		makeRoomMove(domint);
		res = lookupEmptyDomainSpot(domint,&spot);
		assert(res != ALREADY_EXISTS);  // We would have detected this before, obviously

		if (res == NO_EMPTY_SPOT)
			return resNoSpaceLeft;
	}
	else if (res == ALREADY_EXISTS)
		return resAlreadyExists;

	DNS_DB::DnsBlock::InternalBlock * place = &blockptr[spot];
	assert((!(place->header & DNS_DB::DnsBlock::flagUsed) && !(place->header & DNS_DB::DnsBlock::flagDomain)));

	// Insert the new register
	memset(place, 0, sizeof(InternalBlock));
	place->header = DNS_DB::DnsBlock::flagUsed | DNS_DB::DnsBlock::flagDomain;
	memcpy(place->data.domain.domain, domint, MAX_DNS_SIZE);
	bitmap->setBit(spot,true);

	#ifdef EXTRA_CHECK
	checkBM();
	#endif

	return resOK;
}

bool DNS_DB::DnsBlock::addDomainIpv4(const char * domint, const IPv4_Record & iprec) {
	return addDomainIpv4_int(domint, iprec, true);
}

bool DNS_DB::DnsBlock::addDomainIpv4_int(const char * domint, const IPv4_Record & iprec, bool ret) {
	DNS_DB::DnsBlock::InternalBlock * ptr = lookupDomain(domint);
	if (ptr == 0)
		return false;

	// Take a look to see whether we can make use of an existing record chain
	do {
		if (ptr->header & DNS_DB::DnsBlock::flagDomain) {
			for (int i = 0; i < 2; i++)
				if (ptr->data.domain.records[i].ip == 0) {
					ptr->data.domain.records[i] = iprec;
					return true;
				}
		}
		else {
			for (int i = 0; i < 5; i++)
				if (ptr->data.records.records[i].ip == 0) {
					ptr->data.records.records[i] = iprec;
					return true;
				}
		}

		ptr++;
	} while ( ptr != endptr && (ptr->header & DNS_DB::DnsBlock::flagUsed) && !(ptr->header & DNS_DB::DnsBlock::flagDomain));

	// We reached here, there is no block which can be reused, try to allocate
	// the next block
	if (ptr != endptr && !(ptr->header & DNS_DB::DnsBlock::flagUsed)) {
		memset(ptr, 0, sizeof(InternalBlock));
		ptr->header = DNS_DB::DnsBlock::flagUsed;
		ptr->data.records.records[0] = iprec;
		updateBM(); // FIXME do this with bit set!
		return true;
	}
	else if (ret) {
		// Try to move blocks away, only once!
		makeRoomMove(domint);
		// Try again now
		return addDomainIpv4_int(domint, iprec, false);
	}
	return false;
}

// Tries to move some records down and make room for our domain
// TODO in order to support deleting registers we should tightly 
// pack the registers at some point, so we can recover space before
void DNS_DB::DnsBlock::makeRoomMove(const char * domain) {
	// Assume we do not have an empty spot for ourselves. Therefore
	// look for the place we should be and move all the nodes down one
	// position
	int p = 0;

	int res = lookupEmptyDomainSpot(domain, &p);
	assert(res == NO_EMPTY_SPOT || res == ALREADY_EXISTS);

	for (p; p < numBlocks; p++) {
		DNS_DB::DnsBlock::InternalBlock * ptr = &blockptr[p];
		// Stop after we find our spot
		if ((ptr->header & flagUsed) && (ptr->header & DNS_DB::DnsBlock::flagDomain)) {
			if ( !less(ptr->data.domain.domain, domain) ) {
				// If the domain exists move to the last block of it
				if (memcmp(ptr->data.domain.domain, domain, MAX_DNS_SIZE) == 0) {
					do {
						p++;
						ptr = &blockptr[p];
					} while (ptr != endptr && (ptr->header & DNS_DB::DnsBlock::flagUsed) && !(ptr->header & DNS_DB::DnsBlock::flagDomain));
				}
				break;
			}
		}
	}

	// We should not have space after us, otherwise why are we getting called?
	assert((p == numBlocks) || (blockptr[p].header & DNS_DB::DnsBlock::flagDomain));

	if (p == numBlocks)
		return;

	#ifdef EXTRA_CHECK
	checkBM();
	#endif

	// Look for the first empty slot, and move the N slots to make room
	int tomove = 1;
	InternalBlock * ptrl = &blockptr[p+1];
	while (ptrl != endptr) {
		if (!(ptrl->header & flagUsed)) {
			// Move N consec elements down, to make room at ptr
			memmove(&blockptr[p+1], &blockptr[p], tomove*sizeof(InternalBlock));
			memset (&blockptr[p], 0, sizeof(InternalBlock));
			break;
		}
		else
			tomove++;
			
		ptrl++;
	}
	
	if (ptrl == endptr)
		return;

	// Update the bitmask
	bitmap->setBit(p+tomove, true);
	bitmap->setBit(p, false);

	#ifdef EXTRA_CHECK
	checkBM();
	#endif

	// It might happen that we do not have room :(
}

// Create a new DnsBlock and move some registers there using domint as hint
void DNS_DB::DnsBlock::splitBlock(const char * domint, DNS_DB::DnsBlockPtr & newblk) {
	int pos = -1;
	// Just split in 1/16 chunks, to minimize spill
	for (int start = 8*numBlocks/16; start >= 0; start -= numBlocks/16) {
		for (int i = start; i < numBlocks-16; i++) {
			DNS_DB::DnsBlock::InternalBlock * ptr = &blockptr[i];
			if ((ptr->header & DNS_DB::DnsBlock::flagUsed) && (ptr->header & DNS_DB::DnsBlock::flagDomain)) {
				pos = i;
				break;
			}
		}
		if (pos >= 0) break;
	}

	assert(pos >= 0 && pos < numBlocks);

	// Just memcpy the regs after and then zero the old ones
	int regs_after  = numBlocks - pos;
	
	memcpy(newblk->blockptr, &this->blockptr[pos], sizeof(InternalBlock)*regs_after);
	memset(&this->blockptr[pos], 0, sizeof(InternalBlock)*regs_after);

	this->updateBM();
	newblk->updateBM();
}

void DNS_DB::DnsBlock::getMaxDomain(char *d) const {
	for (int i = numBlocks-1; i >= 0; i--) {
		if ((blockptr[i].header & flagUsed) && (blockptr[i].header & flagDomain)) {
			memcpy(d, blockptr[i].data.domain.domain, MAX_DNS_SIZE);
			return;
		}
	}
	assert(0 && "getMaxDomain failed");
}
void DNS_DB::DnsBlock::getMinDomain(char *d) const {
	for (int i = 0; i < numBlocks; i++) {
		if ((blockptr[i].header & flagUsed) && (blockptr[i].header & flagDomain)) {
			memcpy(d, blockptr[i].data.domain.domain, MAX_DNS_SIZE);
			return;
		}
	}
	assert(0 && "getMinDomain failed");
}

void DNS_DB::DnsBlock::check() const {
	char prev[MAX_DNS_SIZE] = {0};
	bool last_empty = true; // Cannot start with IP record
	for (int i = 0; i < numBlocks; i++) {
		// Make sure all domains are in order
		if ((blockptr[i].header & flagUsed) && (blockptr[i].header & flagDomain)) {
			if (!less(prev, blockptr[i].data.domain.domain)) {
				fprintf(stderr, "Error in block %d, unsorted record!\n", blockid);
				memcpy(prev, blockptr[i].data.domain.domain, MAX_DNS_SIZE);
			}
		}
		// Make sure there is no gap between a Domain and IP records
		if ((blockptr[i].header & flagUsed) && !(blockptr[i].header & flagDomain)) {
			if (last_empty) {
				fprintf(stderr, "Error in block %d, hole found!\n", blockid);
			}
		}
		last_empty = ((blockptr[i].header & flagUsed) == 0);
	}

	
	
}



/** Iterator stuff */

// Iterator for DnsBlock: Goto the first domain (or to the end, if no domains at all!)
DNS_DB::DnsBlock::Iterator::Iterator (int blkid, int n, DNS_DB * dbref) : p(n), block_id(blkid), db(dbref) {
	DnsBlockPtr block = db->getBlock(blkid);
	while (&block->blockptr[p] != block->endptr && 
		!(block->blockptr[p].header & DNS_DB::DnsBlock::flagDomain) && 
		!(block->blockptr[p].header & DNS_DB::DnsBlock::flagUsed)) {

		p++;
	}
}

void DNS_DB::DnsBlock::Iterator::next() {
	DnsBlockPtr block = db->getBlock(block_id);
	do {
		p++;
	} while (&block->blockptr[p] != block->endptr && 
		!(block->blockptr[p].header & DNS_DB::DnsBlock::flagDomain) && 
		!(block->blockptr[p].header & DNS_DB::DnsBlock::flagUsed));
}

bool DNS_DB::DnsBlock::Iterator::end() const {
	DnsBlockPtr block = db->getBlock(block_id);
	int i = p;
	do {
		i++;
	} while (&block->blockptr[i] != block->endptr && 
		!(block->blockptr[i].header & DNS_DB::DnsBlock::flagDomain) && 
		!(block->blockptr[i].header & DNS_DB::DnsBlock::flagUsed));

	return &block->blockptr[i] == block->endptr;
}

std::string DNS_DB::DnsBlock::Iterator::getDomain() {
	char tmp [MAX_DNS_SIZE];
	char tmp2[MAX_DNS_SIZE*2];
	getDomain(tmp);
	idom2domain(tmp, tmp2);
	return std::string(tmp2);
}


