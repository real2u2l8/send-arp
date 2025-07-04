#pragma once

#include "mac.h"
#include "ip.h"

/**
 * @brief ARP(Address Resolution Protocol) 헤더 구조체
 * @details 
 * ARP 프로토콜의 헤더를 나타내는 구조체입니다.
 * 네트워크 상에서 IP 주소를 물리적인 MAC 주소로 대응(매핑)시키기 위해 사용됩니다.
 * 
 * 주요 필드:
 * - hrd_: 하드웨어 타입 (이더넷 등)
 * - pro_: 프로토콜 타입
 * - hln_: 하드웨어 주소 길이 (MAC의 경우 6)
 * - pln_: 프로토콜 주소 길이 (IPv4의 경우 4)
 * - op_: Operation 코드 (요청/응답 등)
 * - smac_: 출발지 MAC 주소
 * - sip_: 출발지 IP 주소
 * - tmac_: 목적지 MAC 주소
 * - tip_: 목적지 IP 주소
 */
#pragma pack(push, 1)
struct ArpHdr final {
	uint16_t hrd_;
	uint16_t pro_;
	uint8_t hln_;
	uint8_t pln_;
	uint16_t op_;
	Mac smac_;
	Ip sip_;
	Mac tmac_;
	Ip tip_;

	uint16_t hrd() { return ntohs(hrd_); }
	uint16_t pro() { return ntohs(pro_); }
	uint8_t hln() { return hln_;}
	uint8_t pln() { return pln_;}
	uint16_t op() { return ntohs(op_); }
	Mac smac() { return smac_; }
	Ip sip() { return ntohl(sip_); }
	Mac tmac() { return tmac_; }
	Ip tip() { return ntohl(tip_); }

	// HardwareType(hrd_)
	enum: uint16_t {
		NETROM = 0, // from KA9Q: NET/ROM pseudo
		ETHER = 1, // Ethernet 10Mbps
		EETHER = 2, // Experimental Ethernet
		AX25 = 3, // AX.25 Level 2
		PRONET = 4, // PROnet token ring
		CHAOS = 5, // Chaosnet
		IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
		ARCNET = 7, // ARCnet
		APPLETLK = 8, // APPLEtalk
		LANSTAR = 9, // Lanstar
		DLCI = 15, // Frame Relay DLCI
		ATM = 19, // ATM
		METRICOM = 23, // Metricom STRIP (new IANA id)
		IPSEC = 31 // IPsec tunnel
	};

	// Operation(op_)
	enum: uint16_t {
		Request = 1, // req to resolve address
		Reply = 2, // resp to previous request
		RevRequest = 3, // req protocol address given hardware
		RevReply = 4, // resp giving protocol address
		InvRequest = 8, // req to identify peer
		InvReply = 9 // resp identifying peer
	};
};
typedef ArpHdr *PArpHdr;
#pragma pack(pop)
