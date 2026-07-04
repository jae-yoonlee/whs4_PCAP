# whs4_PCAP

이 저장소는 TCP 패킷을 캡처하고 Ethernet/IP/TCP 헤더와 HTTP 페이로드를 출력하는 PCAP 기반 스니퍼 예제입니다.

## 빌드

```bash
make
```

## 실행

실시간 캡처:

```bash
sudo ./sniff
```

저장된 pcap 파일 분석:

```bash
./sniff capture.pcap
```

## 필요 패키지

```bash
sudo apt update
sudo apt install -y libpcap-dev build-essential
```

## 참고

- `sniff.c`와 `sniff_improved.c`는 동일한 동작을 수행합니다.
- HTTP 요청/응답 페이로드는 사람이 읽기 쉬운 형태로 출력됩니다.
- 종료하려면 Ctrl+C를 누르세요.
