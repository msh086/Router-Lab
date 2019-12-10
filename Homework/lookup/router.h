#include <stdint.h>

/**
 * Interval for multicast whole table
 */
#define MULTICAST_SEC 5
/**
 * Time for time out an entry
 */
#define TIMEOUT_SEC 30
/**
 * Time for delete a timed out entry
 */
#define DELETION_SEC 50
/**
 * Cool down for triggered update
 */
#define TRIGGERED_CD (rand() % 5 + 1)
/**
 * Time for refresh routing table
 */
#define REFRESH_SEC 5

typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
    uint32_t metric; // little endian, while RipEntry.metric is in  big endian
    uint64_t timestamp; // to get rid of entries that haven't been updated for too long
    uint32_t change_flag; // if the entry has been changed
    //uint32_t learnt_from_if; // the if index this entry is learnt from, for split horizon
} RoutingTableEntry;
