#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * ARM uses little endian
 * load 0x01020304 from packet will result in 0x04030201
 */
uint32_t loadBigEndian(const uint8_t* src){
	return *(const uint32_t*)src;
}

/**
 * load little endian data from packet, 0x01020304 will result in 0x01020304
 */
uint32_t loadLittleEndian(const uint8_t* src){
	uint32_t ans = 0;
	for(int i = 0; i < 4; i++){
		ans <<= 8;
		ans |= *src;
		src++;
	}
	return ans;
}

void saveBigEndian(uint8_t* dst, uint32_t data){
	*(uint32_t*)dst = data;
}

void saveLittleEndian(uint8_t* dst, uint32_t data){
	dst += 3;
	for(int i = 3; i >= 0; i--){
		*dst = data & 0xff;
		dst--;
		data >>= 8;
	}
}

bool checkMask(const uint8_t* ptr){
	uint32_t mask = loadLittleEndian(ptr);
	while(mask & 0x80000000)
		mask <<= 1;
	return mask == 0;
}


/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
	uint16_t totalLength = (packet[2] << 8) + packet[3];
	// printf("totalLength: %hu\n", totalLength);
	if(totalLength > len)
		return false;
	const uint8_t* ptr = packet;
	uint8_t headerLength = (packet[0] & 0xf) << 2;
	// printf("headerLength: %hhu\n", headerLength);
	// skip the IP header
	ptr += headerLength; 
	totalLength -= headerLength;
	// skip UDP
	ptr += 8;
	totalLength -= 8;
	// check RIP2 header
	if(ptr[0] != 1 && ptr[0] != 2) // invalid Command
		return false;
	if(ptr[1] != 2) // invalid Version
		return false;
	if(ptr[2] != 0 || ptr[3] != 0) // invalid ZERO
		return false;
	uint8_t cmd = ptr[0];
	output->command = cmd; // store Command
	// skip RIP2 header
	ptr += 4;
	totalLength -= 4;
	int pos = 0;
	// Command = 1, Request, Family = 0
	// Command = 0, Response, Family = 2
	while(totalLength >= 20 && pos < RIP_MAX_ENTRY){ // check Route Entries
		if(ptr[0] != 0 || cmd == 1 && ptr[1] != 0 || cmd == 0 && ptr[1] != 2) // invalid Family
			return false;
		if(ptr[2] != 0 || ptr[3] != 0) // invalid Tag
			return false;
		if(!checkMask(ptr + 8)) // invalid Mask
			return false;
		if(ptr[16] != 0 || ptr[17] != 0 || ptr[18] != 0 || ptr[19] == 0 || ptr[19] > 16) // invalid Metric
			return false;
		uint32_t* ptr32 = (uint32_t*)ptr;
		output->entries[pos].addr = loadBigEndian(ptr + 4);
		output->entries[pos].mask = loadBigEndian(ptr + 8);
		output->entries[pos].nexthop = loadBigEndian(ptr + 12);
		output->entries[pos].metric = loadBigEndian(ptr + 16);
		pos++;
		ptr += 20; // 5 words
		totalLength -= 20;
	}
	output->numEntries = pos;
	return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
	uint8_t* ptr = buffer;
	ptr[0] = rip->command;
	ptr[1] = 2; // version
	ptr[2] = ptr[3] = 0; // ZERO
	// skip RIP2 header
	ptr += 4;
	uint32_t entryCount = rip->numEntries;
	uint8_t family = rip->command == 1 ? 0 : 2;
	for(int i = 0; i < entryCount; i++){
		// set family
		ptr[0] = 0;
		ptr[1] = family;
		// set tag
		ptr[2] = ptr[3] = 0;
		uint32_t* ptr32 = (uint32_t*)ptr;
		// set IP
		saveBigEndian(ptr + 4, rip->entries[i].addr);
		// set mask
		saveBigEndian(ptr + 8, rip->entries[i].mask);
		// set nexthop
		saveBigEndian(ptr + 12, rip->entries[i].nexthop);
		// set metric
		saveBigEndian(ptr + 16, rip->entries[i].metric);
		
		ptr += 20; // 5 words
	}
	return 4 + 20 * entryCount;
}
