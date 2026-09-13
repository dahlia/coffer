Delegate synthetic fixtures
===========================

모든 값은 Coffer가 테스트를 위해 만든 synthetic 문자열이다. 실제 Apple 계정,
토큰 또는 capture에서 유래한 값은 없으며 sanitization할 실제 자료도 없었다.
외부 구현 코드를 가져오거나 변환하지 않았다.

 -  *request.plist*: 최소 프로토콜 사실에 맞춰 직접 작성한 byte-exact XML이다.
    Account `synthetic&<"'>@example.invalid`, PET `SYNTHETIC:PET<&"'>`,
    client-id `synthetic<&"'>-client`로 다섯 XML escape와 PET colon을 검증한다.
 -  *basic.txt*: 동일한 synthetic account/PET의 독립 Basic oracle이다.
    Python 표준 라이브러리 `base64.b64encode`로 아래 입력을 ASCII로 인코딩한
    결과에 `Basic `을 붙였으며 Rust 구현의 출력을 복사하지 않았다.
 -  *success.plist*: 두 integer status 0, 원문 DSID, 구분된 MME/CloudKit token
    및 버릴 unknown token/URL을 손으로 구성했다. Parser가 반환해야 할 값은
    *tests/delegate.rs*의 literal assertion으로 독립 지정했다.

~~~~ python
import base64

account = "synthetic&<\"'>@example.invalid"
pet = "SYNTHETIC:PET<&\"'>"
print("Basic " + base64.b64encode((account + ":" + pet).encode("ascii")).decode("ascii"))
~~~~

추가 Basic 검증은 공개 [RFC 7617 §2]의 `Aladdin`/`open sesame` 예제를 사용한다.
Session 연결 테스트는 기존 Coffer SRP synthetic vector로 만든 Session을
사용하며, 그 account/PET Basic literal도 위와 같은 Python 표준 라이브러리로
생성했다. Malformed/duplicate/type/oversize/depth 테스트는 성공 fixture의
독립적인 변형이다. 이 fixture는 Coffer subset을 검증하며 Apple endpoint
수락이나 호환성의 증거가 아니다. 테스트가 실제 provider, secret store 또는
endpoint를 호출하지 않는다.

[RFC 7617 §2]: https://www.rfc-editor.org/rfc/rfc7617.html#section-2
