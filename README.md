무차별 대입 공격 방어(Brute Force Attack Defend)

해당 프로젝트는 https://github.com/hoon37/Ban_REMOTE_MSSQL 여기로 부터 이동된 프로젝트입니다.

This project has been moved from here at https://github.com/hoon37/Ban_REMOTE_MSSQL.

기본 사용방법과 동작에 대한 개념은 이전 버전과 동일합니다.

The concept of default usage and behavior is the same as previous versions.

다만, 설정이 ini에서 json으로 바뀌었으며 기반 Flatform이 .NET Framework에서 .NET6로 전환되었으며 일부 문제점이 수정되었습니다.

However, the setting has changed from ini to json, the underlying platform has shifted from .NET Framework to .NET6, and some problems have been corrected.

변경된 사용법은 아래 주소를 참고해 주십시오.

Please refer to the address below for the changed usage.

https://cliel.tistory.com/entry/%EB%AC%B4%EC%B0%A8%EB%B3%84-%EB%8C%80%EC%9E%85-%EA%B3%B5%EA%B2%A9-%EB%B0%A9%EC%96%B4-%EB%8F%84%EA%B5%AC-Brute-Force-Attack-Depend-Tool-BanServer

변경사항
1. 26년1월
- .NET6에서 .NET10으로 전환, 관련 Package교체
- 통합이던 Ban_Server를 REMOTE 방어용인 Ban_Server와 MSSQL 방어용인 Ban_MSSQL로 분리 (기존 통하본은 중대한 오류를 유발할 수 있음!)
- MSSQL부분 EventLog 추가

Changes Log
1. January 2026
- Transition from .NET 6 to .NET 10, replacing related packages
- Split the previously unified Ban_Server into Ban_Server for REMOTE defense and Ban_MSSQL for MSSQL defense (Using the old version may cause critical errors!)
- Added MSSQL EventLog
