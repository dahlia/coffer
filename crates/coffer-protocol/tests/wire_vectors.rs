// Coffer: a native Linux client for Apple Passwords.
// Copyright (C) 2026  Hong Minhee
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Byte-exact vectors: the pinned SRP known-answer vector, the golden
//! request bodies, and the fixture files derived from them.

mod support;

use std::io::Cursor;

use coffer_protocol::auth::{Authenticator, LoginOutcome};
use coffer_protocol::secret::{AccountName, Password};
use plist::Value;
use support::vector::{self, Vector};
use support::{FixedAnisette, FixedEntropy, ScriptedTransport, block_on, fixture, hex, ok};

fn credentials() -> (AccountName, Password) {
    (
        AccountName::new(vector::ACCOUNT.to_owned()).unwrap(),
        Password::new(vector::PASSWORD.to_owned()),
    )
}

/// Runs the no-2FA happy path against the vector and returns the recorded
/// request bodies.
fn happy_path_requests(v: &Vector) -> Vec<Vec<u8>> {
    let transport = ScriptedTransport::new(vec![
        ok(vector::init_response(v)),
        ok(vector::complete_response(v, None)),
    ]);
    let auth = Authenticator::new(transport, FixedAnisette, FixedEntropy(vector::a_secret()));
    let (account, password) = credentials();
    let outcome = block_on(auth.login(account, password).authenticate()).unwrap();
    assert!(matches!(outcome, LoginOutcome::Authenticated(_)));
    auth.transport()
        .requests()
        .into_iter()
        .map(|r| r.body.expect("POST body").to_vec())
        .collect()
}

#[test]
fn srp_vector_is_internally_consistent() {
    // `compute` asserts that the `srp` server accepts the client's M1 and
    // that the client accepts the server's M2; reaching here means the
    // Apple-variant parameters round-trip.
    let v = vector::compute();
    assert_eq!(v.k.len(), 32);
    assert_eq!(v.m1.len(), 32);
    assert_eq!(v.m2.len(), 32);
    assert!(v.a_pub.len() <= 256);
    assert!(v.b_pub.len() <= 256);
    assert_eq!(v.spd_ciphertext.len() % 16, 0);
}

#[test]
fn srp_vector_matches_pinned_fixture() {
    let v = vector::compute();
    let text = String::from_utf8(fixture("srp/apple_srp_vector.txt")).unwrap();
    let pinned = vector::parse(&text);
    let expect = |name: &str, bytes: &[u8]| {
        assert_eq!(
            hex(&pinned[name]),
            hex(bytes),
            "pinned `{name}` differs from the fresh computation"
        );
    };
    expect("account", vector::ACCOUNT.as_bytes());
    expect("password", vector::PASSWORD.as_bytes());
    expect("salt", vector::SALT);
    expect("iterations", &vector::ITERATIONS.to_be_bytes());
    expect("a", &vector::a_secret());
    expect("b", &vector::b_secret());
    expect("password_key", &v.password_key);
    expect("A", &v.a_pub);
    expect("B", &v.b_pub);
    expect("M1", &v.m1);
    expect("M2", &v.m2);
    expect("K", &v.k);
    expect("spd_key", &v.spd_key);
    expect("spd_iv", &v.spd_iv);
    expect("spd_plaintext", &v.spd_plaintext);
    expect("spd_ciphertext", &v.spd_ciphertext);
    assert_eq!(
        pinned.len(),
        16,
        "unexpected extra entries in the vector file"
    );
}

/// The 2048-bit SRP group prime from RFC 5054, Appendix A, and its generator.
///
/// Written out here, independently of the `srp` crate, so that the proof
/// recomputation below does not share any code with the implementation under
/// test.
const RFC5054_N_2048: &str = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73";
const RFC5054_G: u8 = 2;

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

#[test]
fn client_and_server_proofs_match_an_independent_recomputation() {
    // Recomputes Apple's SRP-6a proofs from the pinned inputs with SHA-256
    // alone:
    //   M1 = H((H(N) xor H(PAD(g))) | H(I) | s | A | B | K)   (RFC 2945 / 5054)
    //   M2 = H(A | M1 | K)
    // where I is the account name, A and B are the trimmed big-endian public
    // values, and K = H(S).  Only K itself is taken from the vector; it needs
    // modular exponentiation to check independently.  The `srp` crate's
    // composition of these hashes is therefore verified against the
    // specification, not against itself.
    let v = vector::compute();
    let n = support::unhex(RFC5054_N_2048);
    assert_eq!(n.len(), 256);
    let mut padded_g = vec![0u8; n.len()];
    padded_g[n.len() - 1] = RFC5054_G;
    let h_n = sha256(&[&n]);
    let h_g = sha256(&[&padded_g]);
    let n_xor_g: Vec<u8> = h_n.iter().zip(&h_g).map(|(a, b)| a ^ b).collect();
    let h_i = sha256(&[vector::ACCOUNT.as_bytes()]);
    let m1 = sha256(&[&n_xor_g, &h_i, vector::SALT, &v.a_pub, &v.b_pub, &v.k]);
    assert_eq!(hex(&m1), hex(&v.m1), "M1 differs from the RFC composition");
    let m2 = sha256(&[&v.a_pub, &m1, &v.k]);
    assert_eq!(hex(&m2), hex(&v.m2), "M2 differs from the RFC composition");
}

#[test]
fn identity_is_omitted_from_the_password_verifier() {
    // Apple's variant computes x = H(s | H(":" | P')) without the account
    // name.  The verifier v = g^x therefore must not depend on the username;
    // a swapped meaning of the `srp` option would change it.
    use sha2::Sha256;
    let client = srp::ClientG2048::<Sha256>::new_with_options(false);
    let key = vector::password_key();
    let a = client.compute_verifier(b"first@example.invalid", &key, vector::SALT);
    let b = client.compute_verifier(b"second@example.invalid", &key, vector::SALT);
    assert_eq!(a, b);
    let standard = srp::ClientG2048::<Sha256>::new_with_options(true);
    let c = standard.compute_verifier(b"first@example.invalid", &key, vector::SALT);
    assert_ne!(
        a, c,
        "the standard variant must differ, or the option is inert"
    );
}

#[test]
fn client_proof_matches_vector_through_the_public_api() {
    // The client under test must produce exactly the pinned A and M1 for the
    // pinned a, salt, B, iteration count, account, and password.
    let v = vector::compute();
    let bodies = happy_path_requests(&v);
    let init = Value::from_reader(Cursor::new(&bodies[0])).unwrap();
    let init = init.into_dictionary().unwrap();
    let request = init.get("Request").unwrap().as_dictionary().unwrap();
    assert_eq!(request.get("A2k").unwrap().as_data().unwrap(), &v.a_pub[..]);
    let complete = Value::from_reader(Cursor::new(&bodies[1])).unwrap();
    let complete = complete.into_dictionary().unwrap();
    let request = complete.get("Request").unwrap().as_dictionary().unwrap();
    assert_eq!(request.get("M1").unwrap().as_data().unwrap(), &v.m1[..]);
}

#[test]
fn request_bodies_match_golden_files() {
    let v = vector::compute();
    let bodies = happy_path_requests(&v);
    assert_eq!(
        String::from_utf8_lossy(&bodies[0]),
        String::from_utf8_lossy(&fixture("gsa/init_request.plist"))
    );
    assert_eq!(bodies[0], fixture("gsa/init_request.plist"));
    assert_eq!(
        String::from_utf8_lossy(&bodies[1]),
        String::from_utf8_lossy(&fixture("gsa/complete_request.plist"))
    );
    assert_eq!(bodies[1], fixture("gsa/complete_request.plist"));
}

#[test]
fn init_request_has_the_documented_shape() {
    let v = vector::compute();
    let bodies = happy_path_requests(&v);
    let root = Value::from_reader(Cursor::new(&bodies[0]))
        .unwrap()
        .into_dictionary()
        .unwrap();
    let header = root.get("Header").unwrap().as_dictionary().unwrap();
    assert_eq!(header.get("Version").unwrap().as_string(), Some("1.0.1"));
    let request = root.get("Request").unwrap().as_dictionary().unwrap();
    let keys: Vec<&str> = request.keys().map(String::as_str).collect();
    assert_eq!(keys, ["A2k", "cpd", "o", "ps", "u"]);
    assert_eq!(request.get("o").unwrap().as_string(), Some("init"));
    assert_eq!(request.get("u").unwrap().as_string(), Some(vector::ACCOUNT));
    let ps: Vec<&str> = request
        .get("ps")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_string().unwrap())
        .collect();
    assert_eq!(ps, ["s2k", "s2k_fo"]);
    let cpd = request.get("cpd").unwrap().as_dictionary().unwrap();
    let cpd_keys: Vec<&str> = cpd.keys().map(String::as_str).collect();
    assert_eq!(
        cpd_keys,
        [
            "X-Apple-I-Client-Time",
            "X-Apple-I-MD",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-RINFO",
            "X-Apple-I-SRL-NO",
            "X-Apple-I-TimeZone",
            "X-Apple-Locale",
            "X-Mme-Device-Id",
            "bootstrap",
            "icscrec",
            "loc",
            "pbe",
            "prkgen",
            "svct",
        ]
    );
    assert!(!cpd.contains_key("X-Mme-Client-Info"));
    assert_eq!(cpd.get("svct").unwrap().as_string(), Some("iCloud"));
    assert_eq!(cpd.get("loc").unwrap().as_string(), Some("en_US"));
}

#[test]
fn complete_request_has_the_documented_shape() {
    let v = vector::compute();
    let bodies = happy_path_requests(&v);
    let root = Value::from_reader(Cursor::new(&bodies[1]))
        .unwrap()
        .into_dictionary()
        .unwrap();
    let request = root.get("Request").unwrap().as_dictionary().unwrap();
    let keys: Vec<&str> = request.keys().map(String::as_str).collect();
    assert_eq!(keys, ["M1", "c", "cpd", "o", "u"]);
    assert_eq!(request.get("o").unwrap().as_string(), Some("complete"));
    assert_eq!(request.get("c").unwrap().as_string(), Some(vector::COOKIE));
    assert_eq!(request.get("u").unwrap().as_string(), Some(vector::ACCOUNT));
}

#[test]
fn response_fixtures_match_fresh_generation() {
    let v = vector::compute();
    assert_eq!(
        fixture("gsa/init_response.plist"),
        vector::init_response(&v)
    );
    assert_eq!(
        fixture("gsa/init_response_error.plist"),
        vector::init_response_error()
    );
    assert_eq!(
        fixture("gsa/complete_response_authenticated.plist"),
        vector::complete_response(&v, None)
    );
    assert_eq!(
        fixture("gsa/complete_response_2fa.plist"),
        vector::complete_response(&v, Some("trustedDeviceSecondaryAuth"))
    );
    assert_eq!(
        fixture("gsa/complete_response_unknown_step.plist"),
        vector::complete_response(&v, Some("synthetic.unsupported.step"))
    );
    assert_eq!(fixture("gsa/validate_ok.plist"), vector::validate_ok());
    assert_eq!(
        fixture("gsa/validate_rejected.plist"),
        vector::validate_rejected()
    );
}

/// Writes every derived fixture to `$COFFER_FIXTURE_OUT`.
///
/// Ignored by default and refuses to run without the variable so that the
/// suite never writes into the source tree on its own.
#[test]
#[ignore = "writes fixture files; run explicitly with COFFER_FIXTURE_OUT set"]
fn write_fixtures() {
    let out = std::path::PathBuf::from(
        std::env::var_os("COFFER_FIXTURE_OUT").expect("COFFER_FIXTURE_OUT must be set"),
    );
    let v = vector::compute();
    let bodies = happy_path_requests(&v);
    std::fs::create_dir_all(out.join("srp")).unwrap();
    std::fs::create_dir_all(out.join("gsa")).unwrap();
    let write = |name: &str, bytes: &[u8]| std::fs::write(out.join(name), bytes).unwrap();
    write("srp/apple_srp_vector.txt", vector::render(&v).as_bytes());
    write("gsa/init_request.plist", &bodies[0]);
    write("gsa/complete_request.plist", &bodies[1]);
    write("gsa/init_response.plist", &vector::init_response(&v));
    write(
        "gsa/init_response_error.plist",
        &vector::init_response_error(),
    );
    write(
        "gsa/complete_response_authenticated.plist",
        &vector::complete_response(&v, None),
    );
    write(
        "gsa/complete_response_2fa.plist",
        &vector::complete_response(&v, Some("trustedDeviceSecondaryAuth")),
    );
    write(
        "gsa/complete_response_unknown_step.plist",
        &vector::complete_response(&v, Some("synthetic.unsupported.step")),
    );
    write("gsa/validate_ok.plist", &vector::validate_ok());
    write("gsa/validate_rejected.plist", &vector::validate_rejected());
}
