
#include <vector>
#include <map>
#include <string>
#include <string.h>
#include <assert.h>
#include <memory>
#include "record.h"
#include "config.h"

#define MAX_DNS_SIZE 35

#define less(a, b)       (strncmp(a, b, MAX_DNS_SIZE) < 0)    // whether a < b
#define less_eq(a, b)    (strncmp(a, b, MAX_DNS_SIZE) <= 0)   // whether a <= b
#define greater(a, b)    (less(b,a))                          // whether a > b
#define greater_eq(a, b) (strncmp(a, b, MAX_DNS_SIZE) >= 0)   // whether a >= b
#define eq(a, b)         (strncmp(a, b, MAX_DNS_SIZE) == 0)   // whether a == b

#define DOMAIN_MIN "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define DOMAIN_MAX "\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255"

bool domain2idom(const char * domain, char * intdom);
void idom2domain(const char * intdom, char * domain);

class DNS_DB {
public:
	enum queryError { resOK, resNoSpaceLeft, resAlreadyExists, resDomainTooLong, resErrOther };

private:

	class Bitmap;
	class DnsBlock;

	typedef std::shared_ptr<DnsBlock> DnsBlockPtr;

	class DnsBlock {
	public:
		DnsBlock(const std::string & file, int blkid);
		DnsBlock(const DnsBlockPtr & other);
		~DnsBlock();

		std::vector <IPv4_Record> getIpsv4(int p) const;
		queryError addDomain(const char * domain);
		bool hasDomain(const char * domint) const;
		bool addDomainIpv4    (const char * domint, const IPv4_Record & iprec);
		bool replaceDomainIpv4(const char * domint, const IPv4_Record & oldred, const IPv4_Record & newrec);

		void check() const;

		void getMaxDomain(char *) const;
		void getMinDomain(char *) const;

		int getID() const { return blockid; }
		int getNumRecords() const { return bitmap->bitCount(); }
		int getNumFreeRecords() const { return numBlocks - bitmap->bitCount(); }

		class Iterator {
		public:
			Iterator(int blkid, const char * domint, DNS_DB * dbref);
			void next();
			bool end() const;
			void getDomain(char * dom);
			std::vector <IPv4_Record> getIpsv4() { return block->getIpsv4(p); }
			std::string getDomain();
		private:
			int p;
			DNS_DB * db;
			DnsBlockPtr block;
		};

		Iterator getIterator(DNS_DB * dbref, const char * domint) { return Iterator(blockid, domint, dbref); }
		
		void splitBlock(const char * domint, DnsBlockPtr & newblk);

		void updateBM();
		void checkBM();

		static unsigned int blockSize;
		static unsigned int numBlocks;

	private:
		struct __attribute__ ((__packed__)) InternalBlock {
			unsigned char header;
			union t_dunion {
				struct __attribute__ ((__packed__)) {
					char domain[MAX_DNS_SIZE];
					IPv4_Record records[2];
				} domain;
				struct __attribute__ ((__packed__)) {
					char padding[3];
					IPv4_Record records[5];
				} records;
				char raw[63];
			} data;
		};

		InternalBlock * lookupDomain(const char * domain) const;
		int lookupEmptyDomainSpot(const char * domain, int * p) const;
		void makeRoomMove(const char * domain);
		bool addDomainIpv4_int(const char * domain, const IPv4_Record & iprec, bool ret);

		InternalBlock * blockptr;
		InternalBlock * endptr;
		int blockid;
		std::shared_ptr<Bitmap> bitmap;

		static unsigned char flagUsed;
		static unsigned char flagDomain;
	};
	
	class Bitmap {
	public:
		Bitmap(int numBits);
		int getFirst(bool set) const;
		int getRightSet (unsigned int pos) const;
		int bitCount() const;
		void clear() { bitm = std::vector<unsigned int> (bitm.size()); }

		void setBit(unsigned int pos, int value) {
			unsigned int idx = pos / (8*sizeof(unsigned int));
			unsigned int off = pos % (8*sizeof(unsigned int));
			if (value)
				bitm[idx] |=  (1<<off);
			else
				bitm[idx] &= ~(1<<off);
		}

		bool getBit(unsigned int pos) const {
			unsigned int idx = pos / (8*sizeof(unsigned int));
			unsigned int off = pos % (8*sizeof(unsigned int));
			return (bitm[idx] & (1<<off)) != 0;
		}
	private:
		std::vector <unsigned int> bitm;
	};

	class DnsIndex {
	public:
		DnsIndex(DNS_DB * d);

		class Iterator {
		public:
			// Modifiers
			Iterator(DnsIndex * i, int n, const char * domint, DNS_DB * dbref) : p(n), idx(i), block_it(i->getBlock(n)->getIterator(dbref, domint)), db(dbref) {}
			void next() {
				if (block_it.end()) {
					p++;
					block_it = idx->getBlock(p)->getIterator(db, 0);
				}
				else
					block_it.next();
			}

			// Query
			bool end() const { return block_it.end() && p == idx->nodes.size()-1; }
			void getDomain(char * dom) { block_it.getDomain(dom); }
			std::string getDomain() { return block_it.getDomain(); }
			std::vector <IPv4_Record> getIpsv4() { return block_it.getIpsv4(); }
		private:
			unsigned int p;
			DnsIndex * idx;
			DnsBlock::Iterator block_it;
			DNS_DB * db;
		};
	
		void serialize(std::string file);
		void unserialize(const std::string & file);

		queryError addDomain(const char * domain);
		bool hasDomain(const char * domain);
		void addIp4Record(const char * domain, const IPv4_Record & record);
		void replaceIpv4(const char * domain, const IPv4_Record & oldrec, const IPv4_Record & newrec);

		void check();

		void setBlkMinMax(int n, const char * vmin, const char * vmax);
		void getBlkMax(int n, char * v);
		void getBlkMin(int n, char * v);
		int addBlock(unsigned int nwblk_id, const char * vmin, const char * vmax);

		Iterator getIterator() { return Iterator(this, 0, 0, database); }
		Iterator getIterator(const char * domint);

		unsigned long getNumberRecords();
		unsigned long getNumberFreeRecords();

	private:
		class __attribute__ ((__packed__)) Node {
		public:
			char min[MAX_DNS_SIZE];  // Max and min
			char max[MAX_DNS_SIZE];  // contained in the block

			uint32_t dnsblock_id; // Id for the DNS block

			static bool lessthan (const Node & a, const Node & b) { return less(a.min,b.min); }
		};

		DnsBlockPtr getBlock(int n) {
			return database->getBlock(nodes[n].dnsblock_id);
		}

		int lookupNode(const char * domain) const;

		std::vector <Node> nodes;
		DNS_DB * database;
		unsigned int current_id;
	};


	class FileMapper {
	public:
		void * mapFile(const std::string & file);
		void flush(void * ptr);
		void unmap(void * ptr);
		void refinc(void * ptr);
		bool fileExists(const std::string & file) const;
		void createFile(const std::string & file, int size) const;
		int getRefs(void * ptr) const;

		static FileMapper& getInstance() {
			static FileMapper INSTANCE;
			return INSTANCE;
		}

	private:
		class MappedFile {
		public:
			int refs;         // Number of mappings
			void * ptr;       // addr mapped
			int fd;           // FD
			int size;         // Size of the mapping
			std::string file; // Name of the file
		};
		std::vector <MappedFile> files;

		void deallocate(int p);
		void flushCached();
	};

	class BlockManager {
	public:
		BlockManager(DNS_DB * db) : tid(0), db(db) {}
		DnsBlockPtr getBlock(int id);

	private:
		void flushUnusedBlocks();

		class CachedBlock {
		public:
			CachedBlock() : t(0) {}
			std::shared_ptr<DnsBlock> b;
			unsigned long t;
		};
		std::map < int, CachedBlock > blocks;
		int tid;
		DNS_DB * db;
	};

	class IpBloomFilter {
	public:

	private:

	};

	// Block manager contains all the cached and used blocks
	BlockManager blockmgr;

	// Index contains the index tree for the blocks
	DnsIndex index;
	std::string db_path;

	void load(std::string path);
	DnsBlockPtr getBlock(int blockid) { return blockmgr.getBlock(blockid); }
	DnsBlock * getNewBlock(int blockid);

	// Internal stuff
	void updateIterators();

public:
	DNS_DB(const std::string & path);
	~DNS_DB();

	// Modifiers
	queryError addDomain(const std::string & domain);
	void addIp4Record(const std::string & domain, const IPv4_Record & record);
	void replaceIpv4(const std::string & domain, const IPv4_Record & oldrec, const IPv4_Record & newrec);

	// Queries
	bool hasDomain(const std::string & domain) { return index.hasDomain(domain.c_str()); }

	// Maintenance
	void check();

	class DomainIterator {
	public:
		friend class DNS_DB;

		// Modify
		DomainIterator(DNS_DB::DnsIndex * idx, const char * domint, DNS_DB * dbref);
		~DomainIterator();
		void next() {
			// Save the current domain to resync
			it.next();
			it.getDomain(current_domain);
		}
		void addIpv4(const IPv4_Record & rec) { db->addIp4Record(getDomain(), rec); }

		// Query
		bool end() const { return it.end(); }
		std::string getDomain() { return it.getDomain(); }
		std::vector <IPv4_Record> getIpsv4() { return it.getIpsv4(); }

	private:
		DnsIndex * index;
		DnsIndex::Iterator it;
		DNS_DB * db;
		char current_domain[MAX_DNS_SIZE];

		void resync();
	};

	DomainIterator getDomainIterator() { return DomainIterator(&index, 0, this); }
	DomainIterator getDomainIterator(const std::string & domain) {
		char domint[MAX_DNS_SIZE];
		if (!domain2idom(domain.c_str(), domint)) {
			fprintf(stderr,"Error in domain name\n");
		}
		return DomainIterator(&index, domint, this);
	}

	unsigned long getNumberRecords() { return index.getNumberRecords(); }
	unsigned long getNumberFreeRecords() { return index.getNumberFreeRecords(); }

private:
	// Iterators, save them here to track DB updates
	std::vector <DomainIterator*> iterators;
};



