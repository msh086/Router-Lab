#include <stdint.h>
typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
    uint32_t metric; // the same as RipEntry.metric
    uint64_t timestamp; // to get rid of entries that haven't been updated for too long
    uint32_t change_flag; // if the entry has been changed
} RoutingTableEntry;
