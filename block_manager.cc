
#include "dns_db.h"

DNS_DB::DnsBlockPtr DNS_DB::BlockManager::getBlock(int id) {
	#define BlockManager_flush_trigger 32
	if (blocks.find(id) == blocks.end()) {
		DnsBlock * nbl = db->getNewBlock(id);
		CachedBlock cb;
		cb.b.reset(nbl);
		
		blocks.emplace(id, cb);

		if (blocks.size() > BlockManager_flush_trigger)
			flushUnusedBlocks();
	}
	return blocks.at(id).b;
}


void DNS_DB::BlockManager::flushUnusedBlocks() {
	// Remove the blocks with less "t"
	#define BlockManager_flush_maximum 16
	while (blocks.size() > BlockManager_flush_maximum) {
		// Look for candidate:
		unsigned long min = ~0;
		std::map < int, CachedBlock >::iterator cand = blocks.end();
		for (std::map< int, CachedBlock >::iterator it = blocks.begin(); it != blocks.end(); ++it) {
			if (it->second.t < min) {
				if (it->second.b.use_count() == 1) {
					cand = it;
					min = it->second.t;
				}
			}
		}

		// Now delete this block if there is only one reference to it
		if (min != ~0) {
			assert(cand->second.b.use_count() == 1);
			blocks.erase(cand);
		}
		else
			break;
	}

	// Make sure no repeated IDs
	#ifdef EXTRA_CHECK
	std::map <int,int> rep;
	for (std::map< int, CachedBlock >::iterator it = blocks.begin(); it != blocks.end(); ++it) {
		int id = it->second.b->getID();
		assert (rep[id] == 0);
		rep[id]++;
	}
	#endif
}



