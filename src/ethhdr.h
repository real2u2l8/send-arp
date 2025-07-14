#pragma once

#include "mac.h"
/**
 * @brief 이더넷(Ethernet) 헤더 구조체
 * @details 
 * 이더넷 프레임의 헤더를 나타내는 구조체입니다.
 * 데이터 링크 계층에서 MAC 주소를 기반으로 통신하기 위해 사용됩니다.
 * 
 * 주요 필드:
 * - dmac_: 목적지 MAC 주소 
 * - smac_: 출발지 MAC 주소
 * - type_: 상위 계층 프로토콜 타입 (IPv4, ARP, IPv6 등)
 */

#pragma pack(push, 1)
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	// Type(type_)
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)
