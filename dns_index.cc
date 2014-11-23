
#include <string>
#include <algorithm>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "dns_db.h"


/** DnsIndex */

int DNS_DB::DnsIndex::lookupNode(const char * domain) const {
	// Look for node which potentially has this domain
	// TODO: Use dicathomic search
	for (unsigned int i = 0; i < nodes.size(); i++) {
		const Node * n = &nodes[i];
		if ( less_eq(n->min, domain) && less(domain, n->max) ) {
			// Return this node
			return i;
		}
	}
	assert(0 && "This should never occur\n");
	return -1;
}

DNS_DB::DnsIndex::DnsIndex(DNS_DB * db) : database(db) {
	Node n;
	n.dnsblock_id = 0;
	memset(n.min, 0, sizeof(n.min));
	memset(n.max,~0, sizeof(n.min));
	nodes.push_back(n);
	current_id = 1;
}

void DNS_DB::DnsIndex::serialize(std::string file) {
	// Write to file
	FILE * fd = fopen(file.c_str(),"wb");
	uint32_t s = nodes.size();
	fwrite(&s, 1, 4, fd);
	for (unsigned int i = 0; i < nodes.size(); i++) {
		fwrite(&nodes[i], 1, MAX_DNS_SIZE*2 + 4, fd);
	}
	fclose(fd);
}

void DNS_DB::DnsIndex::unserialize(const std::string & file) {
	// Read from file
	if (!FileMapper::getInstance().fileExists(file)) {
		fprintf(stderr,"Warning: Could not read DB index!\n");
		return;
	}

	// Discard our own index
	nodes.clear();

	void * fptr = FileMapper::getInstance().mapFile(file);

	uint32_t nblks = *(uint32_t*)fptr;
	char * cptr = (char*)fptr;
	cptr += 4;

	for (unsigned int i = 0; i < nblks; i++) {
		Node * nodeptr = (Node*)cptr;
		nodes.push_back(*nodeptr);
		cptr += MAX_DNS_SIZE*2 + 4;
	}
	FileMapper::getInstance().unmap(fptr);

	// Find the biggest id
	current_id = 0;
	for (unsigned i = 0; i < nodes.size(); i++)
		if (nodes[i].dnsblock_id > current_id)
			current_id = nodes[i].dnsblock_id;
	current_id++;
}

void DNS_DB::DnsIndex::check() {
	// Check consistency
	for (unsigned int i = 0; i < nodes.size(); i++) {
		if (!less(nodes[i].min, nodes[i].max)) {
			fprintf(stderr, "DB index error!!!\n");
		}
	}

	// Make sure the index is sorted
	for (unsigned int i = 1; i < nodes.size(); i++) {
		if (!less(nodes[i-1].min, nodes[i].min) ||
			!  eq(nodes[i-1].max, nodes[i].min)) {

			fprintf(stderr, "DB index error!!!\n");
		}
	}

	for (unsigned int i = 0; i < nodes.size(); i++) {
		DNS_DB::DnsBlockPtr blk = database->getBlock(nodes[i].dnsblock_id);
		blk->check();
	}
}

DNS_DB::DnsIndex::Iterator DNS_DB::DnsIndex::getIterator(const std::string & domain) {
	char domint[MAX_DNS_SIZE];
	domain2idom(domain.c_str(), domint);

	int n = lookupNode(domint);
	return DNS_DB::DnsIndex::Iterator(this, n, database);
}

void DNS_DB::DnsIndex::addIp4Record(const char * domain, const IPv4_Record & record) {
	char domint[MAX_DNS_SIZE];
	if (!domain2idom(domain, domint)) {
		fprintf(stderr, "Domain too long!\n");
		return;
	}

	int n = lookupNode(domint);
	DNS_DB::DnsBlockPtr blk = database->getBlock(nodes[n].dnsblock_id);

	if (!blk->addDomainIpv4(domint, record)) {
		// Ops, just split the Block in two, must be full
		fprintf(stderr, "Block full!\n");
		unsigned int nwblk_id = this->current_id++;
		DnsBlockPtr newblk = database->getBlock(nwblk_id);
		blk->splitBlock(domint, newblk);

		char nodemax[MAX_DNS_SIZE];
		char dommax [MAX_DNS_SIZE];
		getBlkMax(n, nodemax);
		newblk->getMinDomain(dommax);

		// Set new block boundaries
		addBlock(nwblk_id, dommax, nodemax);

		// Just recalculate the max for the other block
		setBlkMinMax(n, 0, dommax);

		// Redo
		n = lookupNode(domint);
		blk = database->getBlock(nodes[n].dnsblock_id);

		assert(blk->addDomainIpv4(domint, record));
	}
}

bool DNS_DB::DnsIndex::hasDomain(const char * domain) {
	char domint[MAX_DNS_SIZE];
	if (!domain2idom(domain, domint))
		return false;

	int n = lookupNode(domint);
	DNS_DB::DnsBlockPtr blk = database->getBlock(nodes[n].dnsblock_id);
	
	return blk->hasDomain(domint);
}

DNS_DB::queryError DNS_DB::DnsIndex::addDomain(const char * domain) {
	char domint[MAX_DNS_SIZE];
	if (!domain2idom(domain, domint))
		return resDomainTooLong;

	int n = lookupNode(domint);
	DNS_DB::DnsBlockPtr blk = database->getBlock(nodes[n].dnsblock_id);

	queryError res = blk->addDomain(domint);

	if (res == resNoSpaceLeft) {
		// Ops, just split the Block in two, must be full
		unsigned int nwblk_id = this->current_id++;
		DnsBlockPtr newblk = database->getBlock(nwblk_id);
		blk->splitBlock(domint, newblk);

		char nodemax[MAX_DNS_SIZE];
		char dommax [MAX_DNS_SIZE];
		getBlkMax(n, nodemax);
		newblk->getMinDomain(dommax);

		// Set new block boundaries
		addBlock(nwblk_id, dommax, nodemax);

		// Just recalculate the max for the other block
		setBlkMinMax(n, 0, dommax);

		// Redo
		n = lookupNode(domint);
		blk = database->getBlock(nodes[n].dnsblock_id);

		res = blk->addDomain(domint);
		assert(res != resNoSpaceLeft);
	}

	// Make sure the blog minimum is consistent
	#ifdef EXTRA_CHECK
	char tmpd[MAX_DNS_SIZE];
	blk->getIterator(database).getDomain(tmpd);
	assert(less_eq(nodes[n].min, tmpd));

	// Make sure it is allright
	char prev[MAX_DNS_SIZE] = {0};
	DnsBlock::Iterator it = blk->getIterator(database);
	while (!it.end()) {
		char curr[MAX_DNS_SIZE];
		it.getDomain(curr);
		assert(less_eq(prev, curr));
		memcpy(prev,curr,MAX_DNS_SIZE);
		it.next();
	}
	#endif

	return res;
}

void DNS_DB::DnsIndex::setBlkMinMax(int n, const char * vmin, const char * vmax) {
	if (vmin) memcpy(nodes[n].min, vmin, MAX_DNS_SIZE);
	if (vmax) memcpy(nodes[n].max, vmax, MAX_DNS_SIZE);
}
void DNS_DB::DnsIndex::getBlkMax(int n, char * v) {
	memcpy(v, nodes[n].max, MAX_DNS_SIZE);
}
void DNS_DB::DnsIndex::getBlkMin(int n, char * v) {
	memcpy(v, nodes[n].min, MAX_DNS_SIZE);
}


int DNS_DB::DnsIndex::addBlock(unsigned int nwblk_id, const char * vmin, const char * vmax) {
	DNS_DB::DnsIndex::Node node;
	node.dnsblock_id = nwblk_id;
	memcpy(node.min, vmin, MAX_DNS_SIZE);
	memcpy(node.max, vmax, MAX_DNS_SIZE);
	nodes.push_back(node);

	// Now sort all the nodes
	std::sort(nodes.begin(), nodes.end(), DNS_DB::DnsIndex::Node::lessthan);

	for (unsigned int i = 0; i < nodes.size(); i++)
		if (nodes[i].dnsblock_id == nwblk_id)
			return i;

	assert(0 && "Should never reach this\n");
	return 0;
}


unsigned long DNS_DB::DnsIndex::getNumberRecords() {
	unsigned long ret = 0;
	for (unsigned int i = 0; i < nodes.size(); i++) {
		ret += this->getBlock(nodes[i].dnsblock_id)->getNumRecords();
	}
	return ret;
}

unsigned long DNS_DB::DnsIndex::getNumberFreeRecords() {
	unsigned long ret = 0;
	for (unsigned int i = 0; i < nodes.size(); i++) {
		ret += this->getBlock(nodes[i].dnsblock_id)->getNumFreeRecords();
	}
	return ret;
}


