# arp-spoofer
# ARP Spoofing 프로그램

## 프로젝트 개요
**send-arp**는 C++로 구현된 ARP 스푸핑 공격 도구입니다. 이 프로그램은 네트워크 보안 교육 및 연구 목적으로 개발되었으며, ARP 테이블 조작을 통해 Man-in-the-Middle 공격을 수행할 수 있습니다.

### 주요 특징
- **다중 호스트 지원**: 여러 쌍의 Sender/Target IP에 대한 동시 공격 가능
- **실시간 패킷 전송**: 1초 간격으로 ARP 감염 패킷 자동 전송
- **자동 주소 탐지**: 공격자의 MAC/IP 주소 자동 탐지 및 설정
- **MAC 주소 수집**: ARP Request를 통한 피해자 MAC 주소 자동 탐지
- **패킷 구조체 활용**: Ethernet + ARP 패킷 구조체를 활용한 효율적인 패킷 생성

### 기술적 구현
- **언어**: C++17
- **네트워크 라이브러리**: libpcap
- **패킷 구조**: 커스텀 Ethernet/ARP 헤더 구조체
- **메모리 관리**: 패딩 없는 패킷 직렬화
- **빌드 시스템**: CMake 3.16+

### 보안 고지사항
⚠️ **주의**: 이 프로그램은 교육 및 연구 목적으로만 사용되어야 합니다. 실제 네트워크에서의 악의적인 사용은 법적 처벌 대상이 될 수 있습니다.

## 소개
이 프로그램은 ARP Spoofing 공격을 수행하는 도구입니다. 네트워크 상에서 ARP 테이블을 조작하여 특정 호스트의 통신을 가로챌 수 있습니다.

## 주요 기능
- 다중 호스트 ARP Spoofing 지원 (여러 쌍의 Sender/Target IP 동시 공격 가능)
- 실시간 ARP 감염 패킷 주기적 전송 (1초 간격)
- 공격자의 MAC/IP 주소 자동 탐지 및 설정
- ARP Request를 통한 희생자 MAC 주소 자동 탐지
- Ethernet + ARP 패킷 구조체를 활용한 패킷 생성 및 전송

## 의존성
- C++17 이상 컴파일러
- CMake 3.16 이상
- libpcap 개발 패키지
- (문서화용) doxygen, graphviz

### Ubuntu/Debian 설치 예시
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libpcap-dev doxygen graphviz
```

## 빌드 방법
```bash
mkdir build && cd build
cmake ..
make
```

## 실행 방법
root 권한이 필요합니다. 네트워크 인터페이스와 타겟 정보를 인자로 입력하세요.
```bash
sudo ./send-arp <interface> <sender ip> <target ip>
```
예시:
```bash
sudo ./send-arp eth0 192.168.0.2 192.168.0.1
```

## 예제/테스트
- (예시) 여러 쌍의 Sender/Target IP를 쉼표로 구분하여 입력 가능
- 테스트 코드는 추후 추가 예정

## 문서화 (Doxygen)
프로젝트의 코드 문서는 Doxygen을 사용하여 생성됩니다.

### Doxygen 설치
- Ubuntu/Debian:
  ```bash
  sudo apt-get install doxygen graphviz
  ```
- CentOS/RHEL:
  ```bash
  sudo yum install doxygen graphviz
  ```
- Fedora:
  ```bash
  sudo dnf install doxygen graphviz
  ```

### 문서 생성 방법
1. 프로젝트 루트 디렉토리에서 다음 명령어 실행:
   ```bash
   doxygen docs/Doxyfile
   ```
2. 생성된 문서는 `docs/html` 디렉토리에서 확인할 수 있습니다.
3. `docs/html/index.html`을 웹 브라우저로 열어 문서를 탐색할 수 있습니다.

### 문서 구성
- 클래스 및 함수 설명
- 소스 코드 구조
- 호출 그래프
- UML 다이어그램

### Shout out to
- gilgil(BoB Lead Mentor) : @gilbertlee