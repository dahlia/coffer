Legacy delegate 인증
====================

`delegate` 모듈은 기존 Session의 password-equivalent token(PET)을 사용해
MME 및 CloudKit token을 받는 명시적 one-shot 인증 API다. 이 구현은 deterministic
오프라인 증거를 제공한다. Live Apple 수락, CloudKit 접근, account-to-credential
완료를 증명하지 않는다.


호출과 소유권
-------------

`ClientIdRef::new`는 caller 소유의 stable client identifier를 검증하고 빌린다.
`DelegateMaterialRef::from_session`은 `Session`의 account 이름, ADSID 및
optional PET를 빌린다. 별도의 `new`는 같은 검증을 caller-provided 문자열에
적용한다. 후자는 인증 성공이나 PET의 진위를 증명하지 않는다. 입력은
clone/serialize를 제공하지 않으며 빌린 원본보다 오래 살 수 없다. Caller가
원본의 수명과 소거를 책임진다.

`DelegateClient::issue`는 검증된 borrow를 소비한다. 호출마다 기존
`AnisetteProvider`를 한 번 호출하고 `Transport::send`를 최대 한 번 호출한다.
Missing PET 또는 잘못된 입력은 두 adapter를 호출하기 전에 실패한다. Anisette
실패/잘못된 값은 send 전에 실패한다. Transport는 기존 계약에 따라 TLS 검증,
응답 크기 제한, redirect 금지와 내부 retry 금지를 지켜야 한다.

결과 `DelegateCredentials`는 원문 string DSID와 서로 다른 `MmeAuthToken`,
`CloudKitToken` owner를 보관한다. 세 문자열은 drop 시 zeroize되고 값에 대한
borrow만 제공한다. 반환된 URL이나 unknown token은 사용하지 않는다. Remote
응답 전체를 검증한 뒤 필요한 값만 보관한다. Clone/serialize/자동 갱신/저장은
제공하지 않는다. 모든 새 secret-bearing 타입의 Debug는 고정 redaction이다.


고정 요청과 실패 정책
---------------------

POST 목적지는 `https://setup.icloud.com/setup/iosbuddy/loginDelegates`다.
Caller나 응답에서 endpoint를 받지 않는다. XML root의 `apple-id`, `password`,
`delegates.com.apple.mobileme` 빈 dictionary, `client-id`를 직렬화한다.
HTTP Basic은 XML과 동일한 account 이름과 PET로 만든다. 별도 ADSID는
`X-Apple-ADSID`에만 넣는다. IdMS/Xcode token 대체는 없다. ASCII subset의 Basic은
[RFC 7617 §2]의 colon 구분 및 Base64를 따른다. Encoding fallback은 없다.

Legacy User-Agent 및 X-Mme-Client-Info는 고정 관찰 profile이다. 기존 anisette
값을 모두 검증하고, client-info 대신 고정 profile을 쓰며 locale은 `loc`와
`X-Apple-Locale` 양쪽에 넣는다. Client-id와 anisette device/local-user-id 사이의
자동 변환이나 생성은 없다.

HTTP 200에서만 XML을 decode한다. 전체 문서의 문법, 중복, scalar 및 깊이 제한을
먼저 검사한다. Root integer status가 nonzero이면 `RootRejected`, root 0 이후
MobileMe delegate integer status가 nonzero이면 `DelegateRejected`다. 양쪽
0에서만 필수 DSID/token을 추출한다. 이 순서에 따라 root rejection은 delegate
schema 확인보다 먼저 반환될 수 있지만, 문서 전체 XML 검증보다 먼저 반환되지
않는다. Missing/wrong-type status 또는 필수 값은 `Schema`다. 숫자 status의
의미를 expiry/2FA/repair로 추정하지 않는다. Integer DSID는 변환하지 않고
거절하며, string DSID의 앞자리 0이나 공백을 정규화하지 않는다.

오류는 static kind/stage만 반환하며 remote/parser/adapter 문자열, 숫자 status,
키 이름 및 source chain을 보관하지 않는다. Provider/transport의 소유한 임의
오류 문자열은 버리기 전에 zeroize한다. Timeout/cancellation 후에는 발급 여부가
미확정일 수 있다. 자동 retry, login, renewal, settings, init, trust, recovery,
Secret Service 또는 후속 URL 호출은 없다.

[RFC 7617 §2]: https://www.rfc-editor.org/rfc/rfc7617.html#section-2


Coffer subset 한도
------------------

| 대상               | 한도/정책                                       |
| ------------------ | ----------------------------------------------- |
| Account 이름       | 1–256 bytes, printable ASCII, colon 금지        |
| Caller client-id   | 1–256 bytes, printable ASCII                    |
| ADSID 및 결과 DSID | 1–1024 bytes, printable ASCII                   |
| PET 및 결과 token  | 1–4096 bytes, printable ASCII                   |
| HTTP/XML body      | 128 KiB                                         |
| XML string/key     | 원문 scalar 각 4096/256 bytes                   |
| XML data           | decode 후 64 KiB, 기존 encoded scalar 한도 유지 |
| XML depth          | root dictionary가 1, 최대 8                     |
| XML markup         | 종료 태그와 declaration 포함 최대 512           |
| XML integer        | 원문 최대 20 bytes, signed i64 범위             |

Printable ASCII는 U+0020–U+007E이며 입력의 공백과 PET colon은 보존한다. XML
entity 표현도 원문 scalar 한도에 포함되므로 decoded 길이가 작더라도 거절될 수
있다. Binary plist, bare dictionary, 임의 markup/DTD/entity 확장은 허용하지
않는다. 기존 *src/tokens/xml.rs*를 최소한의 crate 내부 visibility 변경으로
공유하며, token API의 기존 동작과 한도는 변경하지 않았다. Unknown 필드도 같은
parser로 검증한 뒤 버린다.


증거와 남은 작업
----------------

구현 입력은 coordinator의 *native-auth-implementation-decision.md*
(2026-09-13)에 제공된 최소 프로토콜 사실, 기존 Coffer 코드 및 공개 RFC
7617뿐이다. 외부 reference-only source/전체 schema/원본 연구 보고서 링크는 열지
않았으며 외부 구현의 구조, 표현 또는 알고리즘을 복사/번역/포팅하지 않았다. 최소
사실의 일부는 source 기반 관찰에서 유래하므로 엄밀한 black-box/clean-room
검증을 주장하지 않는다.

*tests/fixtures/delegate/README.md*는 독립 synthetic fixture와 Basic oracle의
출처를 설명한다. 테스트는 byte-exact 요청, 두 계층 성공/거절/type 오류, 전체
문서 검증, 한도, injection, Session/PET borrow, provider/transport 실패,
no retry, redaction 및 compile-fail lifetime/type 경계를 다룬다.

Token lifetime/reuse/rotation, PET 수급, TLS/profile 수락, client-id와
provisioning binding, 등록/동의 부수 효과는 미확정이다. Live 호출 및 실제
계정/토큰/Secret Service 접근은 0회다. Concrete live adapter는 이 leaf에 없다.
Coordinator의 별도 독립 correctness/security review 및 후속 live readiness
검토가 필요하다.


프로토콜 사실의 추적 경로
-------------------------

Coordinator가 분리해 제공한 endpoint, account/PET 입력 및 delegate 응답 경로의
관찰 출처는 [FindMy account 관찰 A]와 [FindMy account 관찰 B]다. A는
`31c7ef762b62c4cfb92d38aa576a127f0adee997`, B는
`3c2b4926252193e9cd265b39fa52252adcbaad4e`에 고정한다. B의 관련 CloudKit 작업은
다른 구현을 조사한 계보가 있으므로 두 저장소를 독립적인 wire 검증으로 세지
않는다. 이 링크는 사실의 추적용이며 source를 Coffer 구현에 복사하거나 적응할
권한을 뜻하지 않는다.

두 status를 반드시 integer 0으로 요구하는 규칙, string-only DSID, printable
ASCII 및 크기 한도는 Coffer가 선택한 fail-closed subset이다. 공개 서버 계약으로
주장하지 않는다. Synthetic fixtures는 이 subset의 직렬화와 거절 동작을
독립적으로 재현한다. 실제 계정에서의 수락 여부는 별도 live 검증이 필요하다.

[FindMy account 관찰 A]: https://github.com/malmeloo/FindMy.py/blob/31c7ef762b62c4cfb92d38aa576a127f0adee997/findmy/reports/account.py
[FindMy account 관찰 B]: https://github.com/parawanderer/FindMy.py/blob/3c2b4926252193e9cd265b39fa52252adcbaad4e/findmy/reports/account.py
