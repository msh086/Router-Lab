#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <stdio.h>

std::vector<RoutingTableEntry> RoutingTable;

void printTable(){
	for(auto it = RoutingTable.begin(); it != RoutingTable.end(); it++)
		it->print();
}

bool hasUpdate = false;

uint32_t masks[33] = {0x0,
	0x1, 0x3, 0x7, 0xf, 
	0x1f, 0x3f, 0x7f, 0xff, 
	0x1ff, 0x3ff, 0x7ff, 0xfff, 
	0x1fff, 0x3fff, 0x7fff, 0xffff, 
	0x1ffff, 0x3ffff, 0x7ffff, 0xfffff, 
	0x1fffff, 0x3fffff, 0x7fffff, 0xffffff, 
	0x1ffffff, 0x3ffffff, 0x7ffffff, 0xfffffff, 
	0x1fffffff, 0x3fffffff, 0x7fffffff, 0xffffffff};
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, const RoutingTableEntry& entry) {
	int length = RoutingTable.size();
	for(int i = 0; i < length; i++){
		if(RoutingTable[i].addr == entry.addr && RoutingTable[i].len == entry.len){ // skip direct networks
			// direct networks should never be updated or deleted
			if(RoutingTable[i].nexthop == 0)
				return;
			if(insert){
				// the same route path.
				if(RoutingTable[i].nexthop == entry.nexthop){
					// different metric, use the latest one
					if(RoutingTable[i].metric != entry.metric){
						RoutingTable[i] = entry;
						// if the new entry marks the route as unreachable
						// timeout immediately and enter deletion
						if(entry.metric == 16)
							RoutingTable[i].timestamp -= TIMEOUT_SEC * 1000;
					}
					// simply reset timer without setting the change flag
					// if already unreachable, don't reset timer
					else if(RoutingTable[i].metric != 16)
						RoutingTable[i].timestamp = entry.timestamp;
				}
				// different route path. use the better one
				else if(RoutingTable[i].metric > entry.metric)
					RoutingTable[i] = entry;
				// from different router but have same metric
				// if the existing entry is halfway to timeout, use the newer one
				// if already unreachable, leave it alone
				else if(entry.metric != 16 && entry.timestamp - RoutingTable[i].timestamp > TIMEOUT_SEC / 2 * 1000)
					RoutingTable[i] = entry;
				
				if(RoutingTable[i].change_flag)
					hasUpdate = true;
			}
			else
				RoutingTable.erase(RoutingTable.begin() + i);
			return;
		}
	}
	// ignore entry with metric of 16, since it means unreachable
	if(insert && entry.metric < 16){
		RoutingTable.push_back(entry);
		printf("Add RTE: %d.%d.%d.%d\n",
			entry.addr & 0xff, 
			(entry.addr >> 8) & 0xff, 
			(entry.addr >> 16) & 0xff,
			entry.addr >> 24);
		hasUpdate = true;
	}
}

uint8_t CommonPrefixLength(uint32_t addr1, uint32_t addr2, int len){
	return (addr1 & masks[len]) == addr2 ? len : 0;
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
	uint8_t maxMatch = 0;
	int matchIndex = -1;
	int length = RoutingTable.size();
	for(int i = 0; i < length; i++){
		int tmpMatch = CommonPrefixLength(addr, RoutingTable[i].addr, RoutingTable[i].len);
		// ignore entries with metric of 16
		if(tmpMatch > maxMatch && RoutingTable[i].metric < 16){
			maxMatch = tmpMatch;
			matchIndex = i;
		}
	}
	if(maxMatch == 0)
		return false;
	*nexthop = RoutingTable[matchIndex].nexthop;
	*if_index = RoutingTable[matchIndex].if_index;
	return true;
}
