Delegate persistence synthetic fixtures
=======================================

모든 값은 Coffer가 이 저장 계약의 offline 검증을 위해 직접 만든 synthetic
값이다. 실제 계정, token, capture 또는 secret store에서 얻은 자료는 없다.
Reference-only 구현의 source를 열거나 복사/번역/적응하지 않았다.

 -  *v1.bin*: `COFFDLGT`, big-endian version 1, `S` 16 bytes slot과
    `A`/`C`/`D`/`M`/`K` 다섯 1-byte payload를 수동 명세로 조합했다.
    Tag는 1부터 5까지이고 각 length는 `00 01`이다. Production encoder의
    출력을 저장한 것이 아니며 구현 전 decode 실패 테스트의 동일한 bytes다.
 -  *issued.plist*: 기존 Coffer delegate 성공 응답의 최소 schema에 따라
    독립 작성한 XML이다. `000-synthetic-dsid`, `SYNTHETIC-STORED-MME`,
    `SYNTHETIC-STORED-CLOUDKIT`만 발급 결과로 사용한다. Source는 기존 Coffer
    *coffer-protocol/DELEGATE.md* 및 그 crate의 synthetic fixture 설명이다.

Malformed/duplicate/version/slot/field-limit 테스트는 *v1.bin*의 독립적인
변형을 만든다. Fake failure injection은 in-memory 상태만 변경한다. 이 증거는
local 저장 계약과 parser 거절 동작을 검증하며 Apple 호환성을 입증하지 않는다.
