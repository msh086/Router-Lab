#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, const RoutingTableEntry& entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern uint16_t ComputeChecksum(uint8_t *packet, size_t len);

uint32_t countLeadingOnes(uint32_t val){
  uint32_t ans = 0;
  while(val){
    val <<= 1;
    ans++;
  }
  return ans;
}

void convertRoutingEntryToRipEntry(const RoutingTableEntry& rte, RipEntry& re){
  re.addr = rte.addr;
  re.mask = 0xffffffff << (32 - rte.len);
  re.nexthop = rte.nexthop;
  re.metric = rte.metric;
}

void convertRipEntryToRoutingEntry(const RipEntry& re, RoutingTableEntry& rte, uint32_t if_index, uint32_t src_addr){
  rte.addr = re.addr;
  rte.len = countLeadingOnes(re.mask);
  rte.if_index = if_index;
  rte.nexthop = src_addr;
  rte.metric = re.metric;
  rte.timestamp = HAL_GetTicks();
  rte.change_flag = 1;
}

void writeHalf(uint8_t* dst, uint16_t val){
  *dst = val >> 8;
  *(dst+1) = val & 0xff;
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2 R1
// 1: 192.168.4.1 R2
// 2: 10.0.2.1 unused
// 3: 10.0.3.1 unused
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};

// 0: 192.168.3.1 R1
// 1: 192.168.4.2 R2
// 2: 0.0.0.0 none
// 3: 0.0.0.0 none
in_addr_t neighbors[N_IFACE_ON_BOARD] = {0x0103a8c0, 0x0204a8c0, 0x0, 0x0};

void confIPHeader(uint32_t src_addr, uint32_t dst_addr, uint8_t ttl, uint32_t rip_len){
  // Version = 4(IP), IHL = 5
  output[0] = 0x45;
  // ttl is not fixed
  output[8] = ttl;
  // src addr
  *((uint32_t*)(output + 12)) = src_addr;
  // dst addr
  *((uint32_t*)(output + 16)) = dst_addr;
  // UDP
  // port = 520
  output[20] = 0x02;
  output[21] = 0x08;
  // write the total length of IP packet into IP header
  // length of IP header = 20B, length of UDP header = 8B
  writeHalf(output + 28, 28 + rip_len);
  // protocol field, use the same protocol with input
  output[9] = packet[9];
  // checksum calculation for ip and udp
  *((uint16_t*)(output + 10)) = ComputeChecksum(output, 0); // len is used so 0 is fine
  // if you don't want to calculate udp checksum, set it to zero
}

void sendWholeTable(uint32_t src_addr, uint32_t dst_addr, uint32_t src_mac, uint32_t if_index, uint8_t ttl){
  // only need to respond to whole table requests in the lab
  RipPacket resp;
  int pos = 0;
  for(auto it = RoutingTable.begin(); pos < RIP_MAX_ENTRY && it != RoutingTable.end(); it++){
    convertRoutingEntryToRipEntry(*it, resp.entries[pos]);
    if(it->nexthop == src_addr) // split horizon
      resp.entries[pos].metric = 16;
    pos++;
  }
  resp.numEntries = pos;
  resp.command = 2; // response
  // assemble rip
  uint32_t rip_len = assemble(&resp, output + 20 + 8);
  // config IP header
  confIPHeader(src_addr, dst_addr, ttl, rip_len);
  // send it back
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
}



void sendUpdated(uint32_t src_addr, uint32_t dst_addr, uint32_t src_mac, uint32_t if_index, uint8_t ttl){
  
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 192.168.3.0/24 if 0
  // 192.168.4.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0xffffff, // big endian, only keep the lower 24 bits
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = 1,      // need only 1 hop for direct connected networks
        .timestamp = HAL_GetTicks(), // init time
        .change_flag = 0  // TODO: should the flag be 1?
    };
    update(true, entry);
  }
  
  // init output buffer
  memset(output, 0, sizeof(output));
  
  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      printf("30s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr = *((uint32_t*)(packet + 12)), 
      dst_addr = *((uint32_t*)(packet + 16));
    // extract src_addr and dst_addr from packet
    // big endian

    // 2. check whether dst is me
    bool dst_is_me = false;
    bool is_multicast = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    
    if(dst_addr == MULTICAST_ADDR) { // 224.0.0.9. multicast
      dst_is_me = true;
      is_multicast = true;
    }
    
    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) { // command type is REQUEST
          // 3a.3 request, ref. RFC2453 3.9.1
          // send only to the requester
          sendWholeTable(is_multicast ? addrs[if_index] : dst_addr, src_addr, src_mac, if_index, 1);
        } else { // command type is RESPONSE
          // 3a.2 response, ref. RFC2453 3.9.2
          // not from RIP port(in UDP header)
          if(packet[20] != 0x02 || packet[21] != 0x08)
            continue;
          // ignore packets from the router itself
          for(int i = 0; i < N_IFACE_ON_BOARD; i++)
            if(memcmp(addrs + i, packet + 12, sizeof(uint32_t) == 0)
              continue;
          // update begin
          RoutingTableEntry rte;
          for(int i = 0; i < rip.numEntries; i++){
            // update metric
            if(rip.entries[i].metric < 16)
              rip.entries[i].metric++;
            convertRipEntryToRoutingEntry(rip.entries[i], rte, if_index, src_addr);
            update(true, rte);
          }
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // if ttl > 0
          if(output[8] != 0x0)
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          else{
            // TODO: ICMP Time Exceeded
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
