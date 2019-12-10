#include <stdint.h>
#include <stdlib.h>

/**
 * Compute checksum starting from packet, with halfWords halfwords, skip the halfword at index checksum_index
 */
uint16_t ComputeChecksum(uint8_t *packet, size_t halfWords, size_t checksum_index){
	uint32_t ans = 0;
	uint32_t limit = 1 << 16;
	uint16_t* iter = (uint16_t*)packet;
	for(int i = 0; i < halfWords; i++){
	  if(i == checksum_index) // the checksum
		  continue;
	  ans += iter[i];
	  if(ans >= limit)
		  ans = (ans & 0xffff) + 1;
	}
	ans = ~ans;
	return ans & 0xffff;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
	uint16_t* iter = (uint16_t*)packet;
	if(ComputeChecksum(packet, (packet[0] & 0xf) << 1, 5) != iter[5])
		return false;
	packet[8]--; // update TTL
	iter[5] = ComputeChecksum(packet, (packet[0] & 0xf) << 1, 5); // update checksum
	return true;
}

