
/** Config file for the DB */

// Maximum memory to map as cache 
// Note the memmaped space could be bigger if it's in use
#define MAX_MEMMAPPED_MEMORY_MB   512

#define BlockManager_flush_maximum   (MAX_MEMMAPPED_MEMORY_MB/1)   // Max mem / Block size
#define BlockManager_flush_trigger   (1.25f*BlockManager_flush_maximum)


