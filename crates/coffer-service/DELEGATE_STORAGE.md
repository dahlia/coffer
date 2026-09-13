Delegate material의 명시적 로컬 저장
====================================

`StoredDelegateCredentials::from_issued`는 발급 결과 `DelegateCredentials`와
caller의 `DelegateBindingRef`를 받아 ADSID, client-id, DSID, MME token,
CloudKit token을 독립적인 zeroizing owner에 복사한다. 모든 길이와 문자를 먼저
검사하고 빈 zeroizing buffer를 충분히 할당한 뒤 복사하므로 secret을 담은 중간
일반 String이나 재할당이 없다. Getter는 명시적인 `expose_*` borrow만 제공한다.
Debug는 고정 redaction이며 오류는 static enum으로 source chain을 갖지 않는다.

이 생성자는 authenticated origin이나 binding의 진위를 증명하지 않는다.
Caller가 기대하는 ADSID/client-id와 발급 결과의 관계를 책임진다. DSID는 별도
필드이며 ADSID와 같다고 추정하지 않는다. PET, password, account 이름은 새
형식에 없다. Token lifetime/expiry/reuse 성공도 추정하지 않는다.


API와 저장 경계
---------------

`DelegateStore::load_delegate(slot, expected)`는 unique item의 slot 및 저장된
ADSID/client-id를 caller 기대값과 정확히 비교한다. `Ok(None)`은 부재만 뜻한다.
`replace_delegate(slot, expected, value)`도 같은 검증을 하며 새 값 자체가
expected와 다르면 backend를 호출하기 전에 실패한다. 기존 item이 corrupt,
unknown version, wrong binding 또는 duplicate이면 보존하고 오류를 반환한다.
명시적인 이 두 호출 외에 자동 저장/조회, migration, renewal, login fallback,
remote 호출 또는 삭제 API는 없다.

기존 `LinuxSecretService::connect`와 `SessionStore::check_available`을
사용한다. Connect는 기존 default collection에 `Service::encrypted`로만
접속한다. Delegate load/replace도 매번 availability를 확인한다. 새로운
backend 선택, plaintext/file/portal fallback, collection 생성은 없다.

GSA v1의 `COFFSESS`, CBOR body, query attributes, 공개 API 및 동작은 변경하지
않는다. Delegate는 같은 opaque `SessionSlot`을 사용하지만 kind는
`delegate-auth-material`, label은 `Coffer delegate authentication material`이다.
Schema/application/slot 외 account나 token 값, account hash를 query나 label에
넣지 않는다. 두 kind가 같은 slot에 공존할 수 있지만 자동 연결이나 migration은
하지 않는다.

한 item이 검색되면 decode/binding 검증 후 해당 object의 `set_secret`을 한 번
호출하므로 provider의 추가 attributes를 보존한다. Item이 없을 때만
`create_item`을 한 번 호출하며 `replace=false`여서 동시 생성된 미검증 record를
암묵적으로 덮어쓰지 않는다. 실패/timeout/cancellation은 이미 적용된 write일 수
있다. Rollback, 다른 item 선택, cleanup, retry를 시도하지 않고 caller에게
돌려준다. 여러 process의 동시 작업은 transaction으로 보호되지 않으므로 caller가
slot별 작업을 직렬화해야 한다. 경쟁 생성은 duplicate를 남길 수 있고 다음 조회는
fail closed한다. 조회와 update 사이 다른 writer의 변경도 이 API가 막지 못한다.


Coffer 전용 local envelope v1
-----------------------------

이 형식은 Apple wire format이 아니다. `COFFDLGT` magic 8 bytes, big-endian
version `0x0001` 2 bytes, raw `SessionSlot` 16 bytes 다음에 아래 다섯 필드가
정확히 순서대로 온다. 각 필드는 tag 1 byte, big-endian u16 byte length,
printable ASCII payload로 구성한다. 전체 envelope 상한은 16 KiB다.

| Tag | 값               | 허용 길이    |
| --- | ---------------- | ------------ |
| 1   | Caller ADSID     | 1–1024 bytes |
| 2   | Caller client-id | 1–256 bytes  |
| 3   | 발급 결과 DSID   | 1–1024 bytes |
| 4   | MME token        | 1–4096 bytes |
| 5   | CloudKit token   | 1–4096 bytes |

Printable ASCII는 U+0020–U+007E다. 공백과 DSID의 leading zero를 정규화하지
않는다. Decoder는 전체 길이, magic/version/slot, 각 tag의 정확한 순서,
길이와 문자, 끝 위치, caller binding을 모두 검사한 뒤에만 문자열을 소유한다.
고정 ascending tag 검사는 duplicate/unknown/reordered/missing 필드를 거절한다.
다섯 번째 필드 이후의 단 한 byte도 trailing으로 거절한다. Decoder의 untrusted
길이는 slicing 전에 bounded 검사하며 parser error에 원문을 넣지 않는다.

기존 CBOR codec을 확장하지 않은 이유는 GSA v1과 저장 계약을 분리하고,
다섯 문자열만을 대상으로 allocation 이전 전체 검증을 쉽게 검토할 수 있게 하기
위해서다. Optional/unknown 필드나 generic map/serde parser는 이 leaf에 필요하지
않다. 이 작은 local encoding은 암호 구현이 아니며 향후 변경에는 명시적 새
version과 별도 검토가 필요하다.


Offline 증거와 남은 한계
------------------------

`FakeDelegateStore::new_connection`은 같은 in-memory backend에 연결하는 새
client다. Decoded credential cache를 공유하지 않으며 Linux adapter와 동일한
private load/replace 알고리즘을 실행한다. 새 connection round trip, 실제
protocol `DelegateCredentials`에서의 복사와 원본 drop, byte-exact fixture, 각
binding 오류, malformed/oversize/duplicate/unknown/trailing, 실패 후 원문 보존,
create/update의 ambiguous failure 후 단일 시도 및 GSA v1 회귀를 테스트한다.
*tests/fixtures/delegate/README.md*에 synthetic fixture provenance를 기록한다.

이 테스트는 실제 D-Bus client connection이나 desktop provider 검증이 아니다.
Live D-Bus/Apple Account/실제 secret 접근은 수행하지 않았다. Oo7/zbus가 이미
수신한 secret의 크기를 확인한 뒤에 Coffer가 bounded copy와 decode를 수행하므로
16 KiB는 D-Bus 수신 계층 전체의 allocation cap을 의미하지 않는다. Backend의
악의적 동작, 인증서/profile 수락, token reuse 및 provider별 동시성/취소 동작은
증명하지 않는다. Coordinator의 독립 correctness/security review와 별도 live
readiness 판단이 필요하다.
