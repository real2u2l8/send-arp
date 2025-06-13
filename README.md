# send-arp
# ARP Spoofing 프로그램

## 소개
이 프로그램은 ARP Spoofing 공격을 수행하는 도구입니다. 네트워크 상에서 ARP 테이블을 조작하여 특정 호스트의 통신을 가로챌 수 있습니다.

## 주요 기능
- 다중 호스트 ARP Spoofing 지원 (여러 쌍의 Sender/Target IP 동시 공격 가능)
- 실시간 ARP 감염 패킷 주기적 전송 (1초 간격)
- 공격자의 MAC/IP 주소 자동 탐지 및 설정
- ARP Request를 통한 희생자 MAC 주소 자동 탐지
- Ethernet + ARP 패킷 구조체를 활용한 패킷 생성 및 전송

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