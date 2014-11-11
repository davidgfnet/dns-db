
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include "dns_db.h"

unsigned int fileSize(int fd) {
	off_t c_offset = lseek(fd, 0, SEEK_CUR);
	off_t eof = lseek(fd, 0, SEEK_END);
	lseek(fd, c_offset, SEEK_SET);

	return eof;
}


/** File Mapper */
#define MAX_MAPPED   (MAX_MEMMAPPED_MEMORY_MB*1024*1024)

void * DNS_DB::FileMapper::mapFile(const std::string & file) {
	// First of all look whether we have this mapping cached
	for (unsigned int i = 0; i < files.size(); i++) {
		if (files[i].file == file) {
			files[i].refs++;
			return files[i].ptr;
		}
	}

	// Free some memory
	flushCached();

	// Create a new mapping
	MappedFile f;
	f.refs = 1;
	f.file = file;
	f.fd = open(file.c_str(), O_RDWR);
	f.size = fileSize(f.fd);
	f.ptr = mmap(0, f.size, PROT_READ|PROT_WRITE, MAP_SHARED, f.fd, 0);

	assert(f.fd >= 0);
	assert(f.ptr != 0);

	files.push_back(f);

	return f.ptr;
}

void DNS_DB::FileMapper::unmap(void * ptr) {
	//std::cout << "File mapper debug dump" << std::endl;
	//for (unsigned int i = 0; i < files.size(); i++)
	//	std::cout << files[i].file << " " << files[i].refs << std::endl;
	
	for (unsigned int i = 0; i < files.size(); i++) {
		if (files[i].ptr == ptr) {
			files[i].refs--;
			return;
		}
	}
	assert(0 && "Couldn't find the mapped file! This should never happen\n");
}

void DNS_DB::FileMapper::flushCached() {
	// Calculate the size of mapped stuff
	int mapped_referenced = 0;
	int mapped_cached = 0;

	for (unsigned int i = 0; i < files.size(); i++) {
		if (files[i].refs > 0)
			mapped_referenced += files[i].size;
		else
			mapped_cached += files[i].size;
	}

	// Free until we get under the maximum or until no cached stuff is mapped
	while (mapped_referenced + mapped_cached > MAX_MAPPED && mapped_cached > 0) {
		// Look for a victim
		for (unsigned int i = 0; i < files.size(); i++) {
			if (files[i].refs == 0) {
				mapped_cached -= files[i].size;
				this->deallocate(i);
				break;
			}
		}
	}
}

void DNS_DB::FileMapper::flush(void * ptr) {
	for (unsigned int i = 0; i < files.size(); i++) {
		if (files[i].ptr == ptr) {
			msync(files[i].ptr, files[i].size, MS_SYNC);
			return;
		}
	}
}

void DNS_DB::FileMapper::deallocate(int p) {
	MappedFile * f = &files[p];
	// Unmap and free
	assert(f->refs == 0);
	if (munmap(f->ptr, f->size) < 0)
		fprintf(stderr, "Could not unmap file!\n");
	if (close(f->fd) < 0)
		fprintf(stderr, "Could not close file!\n");

	files.erase(files.begin() + p);
}

bool DNS_DB::FileMapper::fileExists(const std::string & file) const {
	FILE * fd = fopen(file.c_str(),"rb");
	if (fd == NULL)
		return false;
	fclose(fd);
	return true;
}

void DNS_DB::FileMapper::createFile(const std::string & file, int size) const {
	int fd = open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	fallocate(fd, 0, 0, size);
	close(fd);
}

void DNS_DB::FileMapper::refinc(void * ptr) {
	for (unsigned int i = 0; i < files.size(); i++) {
		if (files[i].ptr == ptr) {
			files[i].refs++;
			return;
		}
	}
	assert(0 && "Couldn't find the mapped pointer! This should never happen\n");
}

int DNS_DB::FileMapper::getRefs(void * ptr) const {
	for (unsigned int i = 0; i < files.size(); i++) {
		if (files[i].ptr == ptr) {
			return files[i].refs;
		}
	}
	assert(0 && "Couldn't find the mapped pointer! This should never happen\n");
}



