#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <ctime>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, const RoutingTableEntry& entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern uint16_t ComputeChecksum(uint8_t *packet, size_t halfWords, size_t checkum_index);
extern std::vector<RoutingTableEntry> RoutingTable;
extern bool hasUpdate;
extern void printTable();

uint32_t countTrailingingOnes(uint32_t val){
  uint32_t ans = 0;
  while(val){
    val >>= 1;
    ans++;
  }
  return ans;
}

void convertRoutingEntryToRipEntry(const RoutingTableEntry& rte, RipEntry& re){
  re.addr = rte.addr;
  // RipEntry.mask is store in big endian
  re.mask = 0xffffffff >> (32 - rte.len);
  re.nexthop = rte.nexthop;
  // RipEntry.metric is stored in big endian
  // while RoutingTableEntry.metric is stored in little endian
  re.metric = rte.metric << 24; 
}

void convertRipEntryToRoutingEntry(const RipEntry& re, RoutingTableEntry& rte, uint32_t if_index, uint32_t src_addr){
  rte.addr = re.addr;
  rte.len = countTrailingingOnes(re.mask);
  rte.if_index = if_index;
  rte.nexthop = src_addr;
  // RipEntry.metric is stored in big endian
  // while RoutingTableEntry.metric is stored in little endian
  rte.metric = re.metric >> 24;
  rte.timestamp = HAL_GetTicks();
  rte.change_flag = 1;
}

void writeHalf(uint8_t* dst, uint16_t val){
  *dst = uint8_t(val >> 8);
  *(dst+1) = uint8_t(val & 0xff);
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2 R1
// 1: 192.168.4.1 R2
// 2: 10.0.2.1 unused
// 3: 10.0.3.1 unused
// 你可以按需进行修改，注意端序
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
//                                     0x0103000a};

in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x0106000a, 0x0107000a};

bool enables[N_IFACE_ON_BOARD] = {true, true, false, false};

// 0: 192.168.3.1 R1
// 1: 192.168.4.2 R2
// 2: 0.0.0.0 none
// 3: 0.0.0.0 none
in_addr_t neighbors[N_IFACE_ON_BOARD] = {0x0103a8c0, 0x0204a8c0, 0x0, 0x0};

void confIPHeader(uint32_t src_addr, uint32_t dst_addr, uint8_t ttl, uint32_t rip_len, bool isRequest = false){
  // Version = 4(IP), IHL = 5
  output[0] = 0x45;
  // ttl is not fixed
  output[8] = ttl;
  // src addr
  *((uint32_t*)(output + 12)) = src_addr;
  // dst addr
  *((uint32_t*)(output + 16)) = dst_addr;
  // UDP
  // src port = 520
  output[20] = 0x02;
  output[21] = 0x08;
  if(!isRequest){
  // dst port = 520
    output[22] = 0x02;
    output[23] = 0x08;
  }
  else
    output[22] = output[23] = 0;
  // UDP length, including UDP header and payload
  writeHalf(output + 24, 8 + rip_len);
  // if you don't want to calculate udp checksum, set it to zero
  // write the total length of IP packet into IP header
  // length of IP header = 20B, length of UDP header = 8B
  writeHalf(output + 2, 28 + rip_len);
  // protocol field, use UDP
  output[9] = 0x11;
  // checksum calculation for ip and udp
  // IHL is always 5, so halfWords = 10; 5 is the checksum pos for IP header
  *((uint16_t*)(output + 10)) = ComputeChecksum(output, 10, 5); 
}

uint32_t confICMP(uint32_t src_addr, uint32_t dst_addr, uint8_t ttl, uint8_t ICMP_type, uint8_t ICMP_code){
  // Version = 4(IP), IHL = 5
  output[0] = 0x45;
  // ttl is not fixed
  output[8] = ttl;
  // src addr
  *((uint32_t*)(output + 12)) = src_addr;
  // dst addr
  *((uint32_t*)(output + 16)) = dst_addr;
  // protocol, use ICMP
  output[9] = 0x01;
  // ICMP header
  output[20] = ICMP_type; // type
  output[21] = ICMP_code; // code
  output[24] = output[25] = output[26] = output[27] = 0; // unused
  // total length, IP header = 20B, ICMP header = 8 + (20 + <= 64)
  uint16_t inputDatagramLength = (((uint16_t)packet[2]) << 8) + packet[3] - 20;
  if(inputDatagramLength > 64)
    inputDatagramLength = 64;
  memcpy(output + 28, packet, inputDatagramLength);
  memset(output + 28 + inputDatagramLength, 0, inputDatagramLength % 2); // pad to complete half words
  // checksum for ICMP header
  *((uint16_t*)(output + 22)) = ComputeChecksum(output + 20, (8 + 20 + inputDatagramLength + 1) >> 1, 1);
  // compute IP packet length
  writeHalf(output + 2, 20 + 8 + inputDatagramLength + 20);
  // checksum for IP header
  *((uint16_t*)(output + 10)) = ComputeChecksum(output, 10, 5); 
  return inputDatagramLength + 20 + 8 + 20;
}

void sendRequest(uint32_t src_addr, uint32_t dst_addr, macaddr_t dst_mac, uint32_t if_index, uint8_t ttl){
  RipPacket req;
  // when family == 0 and metric == 16, it means that whole table should be sent
  req.entries[0].addr = 0;
  req.entries[0].mask = 0;
  req.entries[0].nexthop = 0;
  req.entries[0].metric = 16 << 24;
  req.numEntries = 1;
  req.command = 1; // request
  uint32_t rip_len = assemble(&req, output + 20 + 8);
  confIPHeader(src_addr, dst_addr, ttl, rip_len, true);
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, dst_mac);
  printf("request sent\n");
}

/**
 * Send the whole RoutingTable
 * Split horizon is used
 */
void sendWholeTable(uint32_t src_addr, uint32_t dst_addr, macaddr_t src_mac, uint32_t if_index, uint8_t ttl){
  // only need to respond to whole table requests in the lab
  RipPacket resp;
  int pos = 0;
  for(auto it = RoutingTable.begin(); pos < RIP_MAX_ENTRY && it != RoutingTable.end(); it++){
    if(it->if_index != if_index) // split horizon
      convertRoutingEntryToRipEntry(*it, resp.entries[pos++]);
  }
  // no entry is left after performing split horizon, no need to send
  if(pos == 0){
    printf("nothing to send after split horizon");
    return;
  }
  resp.numEntries = pos;
  resp.command = 2; // response
  // assemble rip
  uint32_t rip_len = assemble(&resp, output + 20 + 8);
  // config IP header
  confIPHeader(src_addr, dst_addr, ttl, rip_len);
  // send it back
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
  printf("whole table sent\n");
}

/**
 * For every entry in RoutingTable, this function checks:
 * -if the entry's deletion timer is due, remove it from table
 * -otherwise, if the entry times out, change its metric to 16 and mark it as changed
 */
void refreshRoutingTable(){
  uint64_t currentTime = HAL_GetTicks();
  int total = RoutingTable.size();
  int iter = 0;
  while(iter < total){
    if(RoutingTable[iter].nexthop == 0){ // direct network, should never be deleted or timed out
      iter++;
      continue;
    }
    // deletion
    if(currentTime - RoutingTable[iter].timestamp > DELETION_SEC * 1000){
      RoutingTable[iter] = RoutingTable[total - 1];
      total--;
      // iter is unchanged, since element at iter is a new one
      continue;
    }
    // timeout
    if(currentTime - RoutingTable[iter].timestamp > TIMEOUT_SEC * 1000){
      RoutingTable[iter].metric = 16;
      RoutingTable[iter].change_flag = 1;
    }
    iter++;
  }
  // remove deleted entries
  for(int i = RoutingTable.size(); i > total; i--)
    RoutingTable.pop_back();
}

/**
 * Clear all change flags in RoutingTable
 */
void clearChangeFlag(){
  for(auto it = RoutingTable.begin(); it != RoutingTable.end(); it++)
    it->change_flag = 0;
  hasUpdate = false;
}

/**
 * Send all entries marked as changed in a triggered update
 * If at least one entry is marked as changed, send packet and return true
 * else return false
 * Note: this function doesn't change the content of RoutingTable
 */
bool sendUpdated(uint32_t src_addr, uint32_t dst_addr, macaddr_t src_mac, uint32_t if_index, uint8_t ttl){
  RipPacket resp;
  int pos = 0;
  for(auto it = RoutingTable.begin(); pos < RIP_MAX_ENTRY && it != RoutingTable.end(); it++){
    if(it->change_flag && it->if_index != if_index)
      convertRoutingEntryToRipEntry(*it, resp.entries[pos++]);
  }
  if(pos == 0)
    return false;
  resp.numEntries = pos;
  resp.command = 2;
  // assemble rip
  uint32_t rip_len = assemble(&resp, output + 20 + 8);
  // config IP header
  confIPHeader(src_addr, dst_addr, ttl, rip_len);
  // send it back
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
  printf("updated sent\n");
  return true;
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  srand(time(0));

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
        //.learnt_from_if = N_IFACE_ON_BOARD // learnt from no one
    };
    update(true, entry);
  }
  
  // init output buffer
  memset(output, 0, sizeof(output));
  
  for(int i = 0; i < N_IFACE_ON_BOARD; i++){
    if(!enables[i])
      continue;
    macaddr_t mac_addr;
    if(HAL_ArpGetMacAddress(i, MULTICAST_ADDR, mac_addr) == 0)
      sendRequest(addrs[i], MULTICAST_ADDR, mac_addr, i, 1);
    else
      printf("get multicast address error when sending request\n");
  }
  
  // for debug
  {
    //macaddr_t mac_addr;
    //HAL_ArpGetMacAddress(0, MULTICAST_ADDR, mac_addr);
    // sendWholeTable(addrs[0], MULTICAST_ADDR, mac_addr, 0, 1);
    // ICMP debug
    //HAL_SendIPPacket(0, output, confICMP(addrs[0], MULTICAST_ADDR, 64, 0xb, 0x0),
    //          mac_addr);
    //printf("ICMP debug\n");
  }
  
  uint64_t last_time = 0;
  // timer for triggered update
  uint64_t triggered_update = 0;
  // timer for refreshing table
  uint64_t refresh_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    // bool surpressTriggeredUpdate = false;
    if (time > last_time + MULTICAST_SEC * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      macaddr_t mac_addr;
      for(int i = 0; i < N_IFACE_ON_BOARD; i++){
        if(!enables[i])
          continue;
        if(HAL_ArpGetMacAddress(i, MULTICAST_ADDR, mac_addr) == 0)
          sendWholeTable(addrs[i], MULTICAST_ADDR, mac_addr, i, 1);
        else
          printf("get multicast address error\n");
      }
      printTable();
      clearChangeFlag();
      printf("%ds Timer\n", MULTICAST_SEC);
      last_time = time;
      // supress triggered update for 1 - 5 seconds
      // triggered_update = last_time + TRIGGERED_CD * 1000;
    }
    
    if(time > refresh_time + REFRESH_SEC * 1000){
      refreshRoutingTable();
      refresh_time += REFRESH_SEC * 1000;
    }
    
    // send triggered update, when cool down is ready and no multicast is pending in 3 seconds
    // only triggered update is restricted by such kind of cool down
    // reception of IP packet is not influenced
    if(time > triggered_update && hasUpdate){ //&& time < last_time + 27 * 1000){
      macaddr_t mac_addr;
      for(int i = 0; i < N_IFACE_ON_BOARD; i++){
        if(enables[i] && HAL_ArpGetMacAddress(i, MULTICAST_ADDR, mac_addr) == 0){
          sendUpdated(addrs[i], MULTICAST_ADDR, mac_addr, i, 1);
        }
      }
      clearChangeFlag();
      triggered_update = time + TRIGGERED_CD * 1000;
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
            if(memcmp(addrs + i, packet + 12, sizeof(uint32_t)) == 0)
              continue;
          // update begin
          RoutingTableEntry rte;
          for(int i = 0; i < rip.numEntries; i++){
            // update metric
            if(rip.entries[i].metric >> 24 < 16)
              rip.entries[i].metric += 1 << 24;
            convertRipEntryToRoutingEntry(rip.entries[i], rte, if_index, src_addr);
            update(true, rte);
          }
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
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
            // ICMP Time Exceeded
            // type = 11(Time Exceeded), code = 0x0(ttl exceeded)
            HAL_SendIPPacket(if_index, output, confICMP(addrs[if_index], src_addr, 64, 0xb, 0x0),
              dst_mac);
            // send a RIP packet after an ICMP packet can lead to error due to none-zero fields in output buffer
            memset(output, 0, sizeof(output));
            printf("ttl exceeded\n");
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for nexthop %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        // type = 0x3(Destination unreachable), code = 0x1(host unreachable)
        HAL_SendIPPacket(if_index, output, confICMP(addrs[if_index], src_addr, 64, 0x3, 0x1),
          dst_mac);
        memset(output, 0, sizeof(output));
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
