
#ifndef _RECORD_H__
#define _RECORD_H__

#include <stdint.h>

#define IPv4 uint32_t
#define Timestamp uint32_t

struct IPv4_Record {
	Timestamp first_seen, last_seen;
	IPv4 ip;
};
static bool operator==(const IPv4_Record& lhs, const IPv4_Record& rhs) {
    return lhs.ip == rhs.ip && lhs.first_seen == rhs.first_seen && lhs.last_seen == rhs.last_seen;
}

#endif

