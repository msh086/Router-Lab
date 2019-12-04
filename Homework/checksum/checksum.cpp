#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint32_t ans = 0;
  uint32_t limit = 1 << 16;
  uint16_t* iter = (uint16_t*)packet;
  int halfWords = (packet[0] & 0xf) << 1;
  for(int i = 0; i < halfWords; i++){
	  if(i == 5) // the checksum
		  continue;
	  ans += iter[i];
	  if(ans >= limit)
		  ans = (ans & 0xffff) + 1;
  }
  ans = ~ans;
  // NOTE: the higher 16 bits of ans are all 1s! Compare the lower 16 bits of ans with checksum!
  return (ans & 0xffff) == iter[5]; 
}
