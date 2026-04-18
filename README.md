# YARA - CAPE Malware Scanner

CAPE Sandbox 분석 결과를 YARA 룰로 스캔하여 악성코드를 탐지하는 도구

##  주요 기능
-  8개 YARA 룰 기반 악성코드 탐지
-  실시간 컬러풀한 터미널 출력
-  Flask 웹 인터페이스 제공
-  IOC 추출 (위협 인텔리전스팀 전달용)
-  MITRE ATT&CK 기법 매핑

##  실행 방법
```bash
# 터미널 스캔 실행
python yara_rules2.py

# 웹 인터페이스 실행  
python web_yara2.py
# → http://localhost:5000 접속
