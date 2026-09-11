Stored-session harness fixtures
===============================

*apptokens-response.plist* is an exact copy of the wholly synthetic protocol
[OpenSSL service-token fixture](../../../../crates/coffer-protocol/tests/fixtures/apptokens/README.md).
Its key, account, IdMS token, cookie, service token, and expiry are invented;
there is no captured account or keyring data. The harness tests persist only
these invented fields in `FakeSessionStore` and open fresh fake connections. No
Apple, Secret Service, support-library helper, or password-manager access
occurs in these tests.
