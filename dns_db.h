
#include <vector>
#include <map>
#include <string>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <memory>
#include "config.h"

#define IPv4 uint32_t
#define Timestamp uint32_t
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

struct IPv4_Record {
	Timestamp first_seen, last_seen;
	IPv4 ip;
};

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
		bool addDomainIpv4(const char * domint, const IPv4_Record & iprec);

		void check() const;

		void getMaxDomain(char *) const;
		void getMinDomain(char *) const;

		int getID() const { return blockid; }
		int getNumRecords() const { return bitmap->bitCount(); }
		int getNumFreeRecords() const { return numBlocks - bitmap->bitCount(); }

		class Iterator {
		public:
			Iterator(int blkid, int n, DNS_DB * dbref);
			void next();
			bool end() const;
			void getDomain(char * dom) { memcpy(dom, db->getBlock(block_id)->blockptr[p].data.domain.domain, MAX_DNS_SIZE); }
			std::vector <IPv4_Record> getIpsv4() { return db->getBlock(block_id)->getIpsv4(p); }
			std::string getDomain();
		private:
			int p;
			int block_id;
			DNS_DB * db;
		};

		Iterator getIterator(DNS_DB * dbref) { return Iterator(blockid, 0, dbref); }
		
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
			Iterator(DnsIndex * i, int n, DNS_DB * dbref) : p(n), idx(i), block_it(i->getBlock(n)->getIterator(dbref)), db(dbref) {}
			void next() {
				if (block_it.end()) {
					p++;
					block_it = idx->getBlock(p)->getIterator(db);
				}
				else
					block_it.next();
			}
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
		void check();

		void setBlkMinMax(int n, const char * vmin, const char * vmax);
		void getBlkMax(int n, char * v);
		void getBlkMin(int n, char * v);
		int addBlock(unsigned int nwblk_id, const char * vmin, const char * vmax);

		Iterator getIterator() { return Iterator(this, 0, database); }
		Iterator getIterator(const std::string & domain);

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

public:
	DNS_DB(const std::string & path);
	~DNS_DB();

	queryError addDomain(const std::string & domain) { return index.addDomain(domain.c_str()); }
	bool hasDomain(const std::string & domain) { return index.hasDomain(domain.c_str()); }
	void addIp4Record(const std::string & domain, const IPv4_Record & record) { index.addIp4Record(domain.c_str(), record); }
	void check();

	class DomainIterator {
	public:
		DomainIterator(DNS_DB::DnsIndex * idx, DNS_DB * dbref);
		void next() { it.next(); }
		bool end() const { return it.end(); }
		std::string getDomain() { return it.getDomain(); }
		std::vector <IPv4_Record> getIpsv4() { return it.getIpsv4(); }
	private:
		DnsIndex::Iterator it;
		DNS_DB * db;
	};

	DomainIterator getDomainIterator() { return DomainIterator(&index, this); }

	unsigned long getNumberRecords() { return index.getNumberRecords(); }
	unsigned long getNumberFreeRecords() { return index.getNumberFreeRecords(); }
};



