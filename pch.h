#pragma once

#include <cstdio>  // C 스타일 입출력 함수 제공
#include <pcap.h>  // 네트워크 패킷 캡처 및 송수신 라이브러리
#include <sys/socket.h> // 소켓 관련 함수 및 구조체 정의
#include <sys/ioctl.h>  // 네트워크 인터페이스 정보 제어용 함수
#include <net/if.h>     // 네트워크 인터페이스 정보 제공
#include <unistd.h>    // 프로세스 관련 함수 제공
#include <cstring>     // 문자열 처리 함수 제공
#include <cstdint>     // 정수 타입 정의 확장
#include <string>
#include <vector>
//#include <arpa/inet.h>
