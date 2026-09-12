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

//! Invented graph metadata around the existing independent OpenSSL vectors.
use super::*;
use zeroize::Zeroizing;

fn scope() -> KeyScope<'static> {
    KeyScope {
        account: "synthetic-account",
        container: "synthetic-container",
        environment: Environment::Production,
        database: Database::Private,
        zone_owner: "synthetic-owner",
        zone_name: "synthetic-zone",
    }
}
fn id(name: &str) -> KeyId<'_> {
    KeyId {
        scope: scope(),
        name,
    }
}
fn key(start: u8) -> UnwrappingKey {
    UnwrappingKey::new(Zeroizing::new(core::array::from_fn(|i| start + i as u8)))
}
fn anchor() -> AnchorInput<'static> {
    AnchorInput {
        id: id("root"),
        key: key(0),
    }
}
fn fixture(name: &str) -> Vec<u8> {
    let hex = match name {
        "self" => include_str!("../../../tests/fixtures/ckks-wrap/self.hex"),
        "child" => include_str!("../../../tests/fixtures/ckks-wrap/child.hex"),
        "grandchild" => include_str!("../../../tests/fixtures/ckks-wrap/grandchild.hex"),
        _ => panic!("unknown synthetic vector"),
    }
    .trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn record<'a>(
    name: &'a str,
    parent: Option<&'a str>,
    class: KeyClass,
    wrapped: &'a [u8],
) -> KeyRecord<'a> {
    KeyRecord {
        id: id(name),
        parent: parent.map(id),
        class,
        wrapped,
    }
}
fn graph<'a>(records: &'a [KeyRecord<'a>]) -> Result<KeyGraph<'a>, HierarchyError> {
    KeyGraph::validate(
        scope(),
        records,
        InputCompleteness::Complete,
        id("root"),
        HierarchyLimits::default(),
    )
}
fn calls() -> usize {
    UNWRAP_CALLS.with(|n| n.replace(0))
}

#[test]
fn existing_vectors_resolve_historical_target_in_every_input_order() {
    let a = fixture("self");
    let b = fixture("child");
    let c = fixture("grandchild");
    let records = [
        record("root", Some("root"), KeyClass::Tlk, &a),
        record("old-tlk", Some("root"), KeyClass::Tlk, &b),
        record("old-class", Some("old-tlk"), KeyClass::ClassC, &c),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let inputs = order.map(|i| records[i]);
        let graph = graph(&inputs).unwrap();
        let anchor = anchor();
        calls();
        let result = graph.unwrap_target(&anchor, id("old-class")).unwrap();
        assert_eq!(result.expose_secret(), key(128).expose_secret());
        assert_eq!(result.id(), id("old-class"));
        assert_eq!(result.class(), KeyClass::ClassC);
        assert_eq!(calls(), 3);
    }
}

#[test]
fn absent_and_explicit_root_shared_parent_and_target_root_work() {
    let a = fixture("self");
    let b = fixture("child");
    for parent in [None, Some("root")] {
        let records = [
            record("root", parent, KeyClass::Tlk, &a),
            record("a", Some("root"), KeyClass::ClassA, &b),
            record("c", Some("root"), KeyClass::ClassC, &b),
        ];
        let graph = graph(&records).unwrap();
        let anchor = anchor();
        for target in ["a", "c", "root"] {
            let output = graph.unwrap_target(&anchor, id(target)).unwrap();
            assert_eq!(
                output.expose_secret(),
                key(if target == "root" { 0 } else { 64 }).expose_secret()
            );
        }
    }
}

#[test]
fn incomplete_empty_and_duplicates_fail_before_crypto() {
    let a = fixture("self");
    let one = record("root", None, KeyClass::Tlk, &a);
    assert_eq!(graph(&[]).unwrap_err(), HierarchyError::EmptyInput);
    assert_eq!(
        KeyGraph::validate(
            scope(),
            &[one],
            InputCompleteness::Incomplete,
            id("root"),
            HierarchyLimits::default()
        )
        .unwrap_err(),
        HierarchyError::IncompleteInput
    );
    for duplicate in [
        one,
        record("root", Some("root"), KeyClass::ClassC, &[0; 80]),
    ] {
        calls();
        assert_eq!(
            graph(&[one, duplicate]).unwrap_err(),
            HierarchyError::DuplicateRecord
        );
        assert_eq!(calls(), 0);
    }
}

#[test]
fn malformed_identifiers_classes_and_all_wrapped_lengths_fail() {
    let a = fixture("self");
    for name in ["", "tlk", "CLASSA", "classa", "classC "] {
        if name != "tlk" {
            assert_eq!(
                KeyClass::try_from(name).unwrap_err(),
                HierarchyError::UnsupportedClass
            );
        }
    }
    for (name, class) in [
        ("tlk", KeyClass::Tlk),
        ("classA", KeyClass::ClassA),
        ("classC", KeyClass::ClassC),
    ] {
        assert_eq!(KeyClass::try_from(name).unwrap(), class);
    }
    assert_eq!(
        graph(&[record("", None, KeyClass::Tlk, &a)]).unwrap_err(),
        HierarchyError::InvalidIdentifier
    );
    let root = record("root", None, KeyClass::Tlk, &a);
    assert_eq!(
        graph(&[root, record("child", Some(""), KeyClass::ClassC, &a)]).unwrap_err(),
        HierarchyError::InvalidIdentifier
    );
    for len in (0..80).chain([81, 1024]) {
        let bad = vec![0; len];
        calls();
        assert_eq!(
            graph(&[root, record("bad", Some("root"), KeyClass::ClassC, &bad)]).unwrap_err(),
            HierarchyError::InvalidWrappedLength
        );
        assert_eq!(calls(), 0);
    }
}

fn foreign_scopes() -> [KeyScope<'static>; 6] {
    [
        KeyScope {
            account: "other",
            ..scope()
        },
        KeyScope {
            container: "other",
            ..scope()
        },
        KeyScope {
            environment: Environment::Development,
            ..scope()
        },
        KeyScope {
            database: Database::Shared,
            ..scope()
        },
        KeyScope {
            zone_owner: "other",
            ..scope()
        },
        KeyScope {
            zone_name: "other",
            ..scope()
        },
    ]
}

#[test]
fn every_scope_component_is_exact_for_nodes_parents_anchors_and_targets() {
    let a = fixture("self");
    let b = fixture("child");
    let root = record("root", None, KeyClass::Tlk, &a);
    let child = record("child", Some("root"), KeyClass::ClassC, &b);
    for foreign in foreign_scopes() {
        let mut altered = child;
        altered.id.scope = foreign;
        assert_eq!(
            graph(&[root, altered]).unwrap_err(),
            HierarchyError::ScopeMismatch
        );
        altered = child;
        altered.parent.as_mut().unwrap().scope = foreign;
        assert_eq!(
            graph(&[root, altered]).unwrap_err(),
            HierarchyError::ScopeMismatch
        );
        let inputs = [root, child];
        let graph = graph(&inputs).unwrap();
        let mut anchor = anchor();
        anchor.id.scope = foreign;
        calls();
        assert_eq!(
            graph.unwrap_target(&anchor, id("child")).unwrap_err(),
            HierarchyError::AnchorBindingMismatch
        );
        anchor.id = id("root");
        assert_eq!(
            graph
                .unwrap_target(
                    &anchor,
                    KeyId {
                        scope: foreign,
                        name: "child"
                    }
                )
                .unwrap_err(),
            HierarchyError::ScopeMismatch
        );
        assert_eq!(calls(), 0);
        assert_eq!(
            KeyGraph::validate(
                scope(),
                &inputs,
                InputCompleteness::Complete,
                KeyId {
                    scope: foreign,
                    name: "root"
                },
                HierarchyLimits::default()
            )
            .unwrap_err(),
            HierarchyError::AnchorBindingMismatch
        );
    }
}

#[test]
fn names_are_not_normalized_and_unknown_targets_do_no_crypto() {
    let a = fixture("self");
    let b = fixture("child");
    for name in ["Not-A-UUID", "e\u{301}", "é", " root", "ROOT"] {
        let records = [
            record("root", None, KeyClass::Tlk, &a),
            record(name, Some("root"), KeyClass::ClassA, &b),
        ];
        let graph = graph(&records).unwrap();
        let mut anchor = anchor();
        assert!(graph.unwrap_target(&anchor, id(name)).is_ok());
        calls();
        assert_eq!(
            graph.unwrap_target(&anchor, id("unknown")).unwrap_err(),
            HierarchyError::UnknownTarget
        );
        anchor.id = id("ROOT");
        assert_eq!(
            graph.unwrap_target(&anchor, id(name)).unwrap_err(),
            HierarchyError::AnchorBindingMismatch
        );
        assert_eq!(calls(), 0);
    }
    let records = [
        record("root", None, KeyClass::Tlk, &a),
        record("é", Some("root"), KeyClass::ClassA, &b),
    ];
    assert_eq!(
        graph(&records)
            .unwrap()
            .unwrap_target(&anchor(), id("e\u{301}"))
            .unwrap_err(),
        HierarchyError::UnknownTarget
    );
}

#[test]
fn all_nodes_require_parents_one_anchor_and_supported_relationships() {
    let a = fixture("self");
    let root = record("root", None, KeyClass::Tlk, &a);
    assert_eq!(
        graph(&[
            root,
            record("unused", Some("missing"), KeyClass::ClassC, &a)
        ])
        .unwrap_err(),
        HierarchyError::MissingParent
    );
    assert_eq!(
        graph(&[root, record("other-root", None, KeyClass::Tlk, &a)]).unwrap_err(),
        HierarchyError::MultipleRoots
    );
    assert_eq!(
        graph(&[record("other-root", None, KeyClass::Tlk, &a)]).unwrap_err(),
        HierarchyError::MissingAnchor
    );
    for class in [KeyClass::ClassA, KeyClass::ClassC] {
        for parent in [None, Some("bad")] {
            assert_eq!(
                graph(&[root, record("bad", parent, class, &a)]).unwrap_err(),
                HierarchyError::UnsupportedRelationship
            );
        }
        for child in [KeyClass::Tlk, KeyClass::ClassA, KeyClass::ClassC] {
            assert_eq!(
                graph(&[
                    root,
                    record("parent", Some("root"), class, &a),
                    record("bad", Some("parent"), child, &a)
                ])
                .unwrap_err(),
                HierarchyError::UnsupportedRelationship
            );
        }
    }
    let mut bad_anchor = root;
    bad_anchor.parent = Some(id("child"));
    assert_eq!(
        graph(&[bad_anchor, record("child", Some("root"), KeyClass::Tlk, &a)]).unwrap_err(),
        HierarchyError::AnchorNotSelfWrapped
    );
    bad_anchor = root;
    bad_anchor.class = KeyClass::ClassA;
    assert_eq!(
        graph(&[bad_anchor]).unwrap_err(),
        HierarchyError::AnchorNotSelfWrapped
    );
}

#[test]
fn unrelated_two_and_three_node_cycles_are_rejected() {
    let a = fixture("self");
    let root = record("root", None, KeyClass::Tlk, &a);
    for records in [
        vec![
            root,
            record("b", Some("c"), KeyClass::Tlk, &a),
            record("c", Some("b"), KeyClass::Tlk, &a),
        ],
        vec![
            root,
            record("b", Some("c"), KeyClass::Tlk, &a),
            record("c", Some("d"), KeyClass::Tlk, &a),
            record("d", Some("b"), KeyClass::Tlk, &a),
        ],
    ] {
        calls();
        assert_eq!(graph(&records).unwrap_err(), HierarchyError::Cycle);
        assert_eq!(calls(), 0);
    }
}

#[test]
fn limits_are_positive_and_cannot_exceed_hard_caps() {
    assert!(HierarchyLimits::new(1024, 1024, 8 * 1024 * 1024, 64).is_ok());
    for limits in [
        (0, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
        (1025, 1, 1, 1),
        (1, 1025, 1, 1),
        (1, 1, 8 * 1024 * 1024 + 1, 1),
        (1, 1, 1, 65),
        (usize::MAX, 1, 1, 1),
        (1, usize::MAX, 1, 1),
        (1, 1, usize::MAX, 1),
        (1, 1, 1, usize::MAX),
    ] {
        assert_eq!(
            HierarchyLimits::new(limits.0, limits.1, limits.2, limits.3).unwrap_err(),
            HierarchyError::InvalidLimits
        );
    }
}

#[test]
fn count_identifier_and_aggregate_limits_have_exact_boundaries() {
    let a = fixture("self");
    let b = fixture("child");
    let records = [
        record("root", None, KeyClass::Tlk, &a),
        record("child", Some("root"), KeyClass::ClassC, &b),
    ];
    let validate = |limits| {
        KeyGraph::validate(
            scope(),
            &records,
            InputCompleteness::Complete,
            id("root"),
            limits,
        )
    };
    assert!(validate(HierarchyLimits::new(2, 1024, 8 * 1024 * 1024, 64).unwrap()).is_ok());
    assert_eq!(
        validate(HierarchyLimits::new(1, 1024, 8 * 1024 * 1024, 64).unwrap()).unwrap_err(),
        HierarchyError::LimitExceeded
    );
    // Counting is defined publicly: all supplied identifier occurrences plus
    // two scope enum bytes per ID, 80 wrapped bytes and two class/parent bytes.
    let scope_bytes = "synthetic-account".len()
        + "synthetic-container".len()
        + "synthetic-owner".len()
        + "synthetic-zone".len()
        + 2;
    let total = scope_bytes
        + (scope_bytes + 4)
        + (scope_bytes + 4 + 82)
        + (scope_bytes + 5 + scope_bytes + 4 + 82);
    assert!(validate(HierarchyLimits::new(2, 1024, total, 64).unwrap()).is_ok());
    assert_eq!(
        validate(HierarchyLimits::new(2, 1024, total - 1, 64).unwrap()).unwrap_err(),
        HierarchyError::LimitExceeded
    );
    let name = "n".repeat(1024);
    let too_long = "n".repeat(1025);
    let boundary = [
        records[0],
        record(&name, Some("root"), KeyClass::ClassC, &b),
    ];
    assert!(graph(&boundary).is_ok());
    assert_eq!(
        graph(&[
            records[0],
            record(&too_long, Some("root"), KeyClass::ClassC, &b)
        ])
        .unwrap_err(),
        HierarchyError::LimitExceeded
    );
    for foreign in [
        KeyScope {
            account: "",
            ..scope()
        },
        KeyScope {
            container: "",
            ..scope()
        },
        KeyScope {
            zone_owner: "",
            ..scope()
        },
        KeyScope {
            zone_name: "",
            ..scope()
        },
    ] {
        assert_eq!(
            KeyGraph::validate(
                foreign,
                &records,
                InputCompleteness::Complete,
                id("root"),
                HierarchyLimits::default()
            )
            .unwrap_err(),
            HierarchyError::InvalidIdentifier
        );
    }
}

#[test]
fn depth_is_checked_for_unselected_branches_and_memoized_suffixes() {
    let a = fixture("self");
    let names: Vec<_> = (0..66).map(|i| format!("node-{i}")).collect();
    let mut records = vec![record("root", None, KeyClass::Tlk, &a)];
    for i in 0..65 {
        records.push(record(
            &names[i],
            Some(if i == 0 { "root" } else { &names[i - 1] }),
            KeyClass::Tlk,
            &a,
        ));
    }
    assert!(graph(&records[..65]).is_ok());
    assert_eq!(graph(&records).unwrap_err(), HierarchyError::LimitExceeded);
    records.reverse();
    assert_eq!(graph(&records).unwrap_err(), HierarchyError::LimitExceeded);
}

#[test]
fn self_wrap_must_return_the_exact_anchor_key() {
    let b = fixture("child");
    let records = [record("root", None, KeyClass::Tlk, &b)];
    calls();
    assert_eq!(
        graph(&records)
            .unwrap()
            .unwrap_target(&anchor(), id("root"))
            .unwrap_err(),
        HierarchyError::AnchorKeyMismatch
    );
    assert_eq!(calls(), 1);
}

#[test]
fn authentication_failure_returns_no_partial_key_and_stops_the_path() {
    let a = fixture("self");
    let b = fixture("child");
    let c = fixture("grandchild");
    for bad_at in 0..3 {
        for offset in 0..80 {
            let mut wrapped = [a.clone(), b.clone(), c.clone()];
            wrapped[bad_at][offset] ^= 1;
            let records = [
                record("root", None, KeyClass::Tlk, &wrapped[0]),
                record("old", Some("root"), KeyClass::Tlk, &wrapped[1]),
                record("target", Some("old"), KeyClass::ClassA, &wrapped[2]),
            ];
            let graph = graph(&records).unwrap();
            calls();
            let error = graph.unwrap_target(&anchor(), id("target")).unwrap_err();
            assert_eq!(error, HierarchyError::KeyAuthenticationFailed);
            assert_eq!(calls(), bad_at + 1);
            assert_eq!(
                wrapped[bad_at][offset],
                [a[offset], b[offset], c[offset]][bad_at] ^ 1
            );
        }
    }
    let records = [record("root", None, KeyClass::Tlk, &a)];
    let wrong = AnchorInput {
        id: id("root"),
        key: key(1),
    };
    calls();
    assert_eq!(
        graph(&records)
            .unwrap()
            .unwrap_target(&wrong, id("root"))
            .unwrap_err(),
        HierarchyError::KeyAuthenticationFailed
    );
    assert_eq!(calls(), 1);
}

#[test]
fn unrelated_ciphertext_is_not_unwrapped_but_its_structure_is_checked() {
    let a = fixture("self");
    let b = fixture("child");
    let records = [
        record("root", None, KeyClass::Tlk, &a),
        record("selected", Some("root"), KeyClass::ClassC, &b),
        record("unselected", Some("root"), KeyClass::ClassA, &[0; 80]),
    ];
    let graph = graph(&records).unwrap();
    let anchor = anchor();
    calls();
    assert!(graph.unwrap_target(&anchor, id("selected")).is_ok());
    assert_eq!(calls(), 2);
    assert_eq!(
        graph.unwrap_target(&anchor, id("unselected")).unwrap_err(),
        HierarchyError::KeyAuthenticationFailed
    );
}

#[test]
fn valid_ciphertext_does_not_authenticate_claimed_name_or_class() {
    let a = fixture("self");
    let b = fixture("child");
    for class in [KeyClass::Tlk, KeyClass::ClassA, KeyClass::ClassC] {
        let records = [
            record("root", None, KeyClass::Tlk, &a),
            record("arbitrary-rebinding", Some("root"), class, &b),
        ];
        let graph = graph(&records).unwrap();
        let anchor = anchor();
        let result = graph
            .unwrap_target(&anchor, id("arbitrary-rebinding"))
            .unwrap();
        assert_eq!(result.expose_secret(), key(64).expose_secret());
        assert_eq!(result.class(), class);
    }
}

#[test]
fn every_input_graph_output_and_error_debug_is_redacted() {
    let a = fixture("self");
    let records = [record("root", None, KeyClass::Tlk, &a)];
    let graph = graph(&records).unwrap();
    let anchor = anchor();
    let result = graph.unwrap_target(&anchor, id("root")).unwrap();
    assert_eq!(format!("{:?}", scope()), "KeyScope(<redacted>)");
    assert_eq!(format!("{:?}", id("root")), "KeyId(<redacted>)");
    assert_eq!(format!("{:?}", records[0]), "KeyRecord(<redacted>)");
    assert_eq!(format!("{anchor:?}"), "AnchorInput(<redacted>)");
    assert_eq!(format!("{graph:?}"), "KeyGraph(<redacted>)");
    assert_eq!(format!("{result:?}"), "ResolvedKey(<redacted>)");
    let error = graph
        .unwrap_target(&anchor, id("private-sentinel"))
        .unwrap_err();
    assert_eq!(error.to_string(), "unknown CKKS target");
    assert_eq!(format!("{error:?}"), "UnknownTarget");
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn hard_node_cap_and_smaller_identifier_and_depth_limits_are_enforced() {
    let a = fixture("self");
    let names: Vec<_> = (0..1024).map(|i| format!("node-{i}")).collect();
    let mut records = vec![record("root", None, KeyClass::Tlk, &a)];
    records.extend(
        names
            .iter()
            .map(|name| record(name, Some("root"), KeyClass::Tlk, &a)),
    );
    assert!(graph(&records[..1024]).is_ok());
    calls();
    assert_eq!(graph(&records).unwrap_err(), HierarchyError::LimitExceeded);
    assert_eq!(calls(), 0);
    let pair = &records[..2];
    // The container is the longest identifier in these two records (19 bytes).
    assert!(
        KeyGraph::validate(
            scope(),
            pair,
            InputCompleteness::Complete,
            id("root"),
            HierarchyLimits::new(2, 19, 10000, 1).unwrap()
        )
        .is_ok()
    );
    assert_eq!(
        KeyGraph::validate(
            scope(),
            pair,
            InputCompleteness::Complete,
            id("root"),
            HierarchyLimits::new(2, 18, 10000, 1).unwrap()
        )
        .unwrap_err(),
        HierarchyError::LimitExceeded
    );
    let chain = [
        records[0],
        record("old", Some("root"), KeyClass::Tlk, &a),
        record("target", Some("old"), KeyClass::ClassC, &a),
    ];
    assert!(
        KeyGraph::validate(
            scope(),
            &chain,
            InputCompleteness::Complete,
            id("root"),
            HierarchyLimits::new(3, 1024, 10000, 2).unwrap()
        )
        .is_ok()
    );
    assert_eq!(
        KeyGraph::validate(
            scope(),
            &chain,
            InputCompleteness::Complete,
            id("root"),
            HierarchyLimits::new(3, 1024, 10000, 1).unwrap()
        )
        .unwrap_err(),
        HierarchyError::LimitExceeded
    );
}

#[test]
fn aggregate_hard_cap_and_checked_arithmetic_reject_oversized_metadata() {
    let a = fixture("self");
    let long = "s".repeat(1024);
    let huge_scope = KeyScope {
        account: &long,
        container: &long,
        zone_owner: &long,
        zone_name: &long,
        ..scope()
    };
    let root_id = KeyId {
        scope: huge_scope,
        name: "root",
    };
    let names: Vec<_> = (0..1023).map(|i| format!("node-{i}")).collect();
    let mut records = vec![KeyRecord {
        id: root_id,
        parent: None,
        class: KeyClass::Tlk,
        wrapped: &a,
    }];
    records.extend(names.iter().map(|name| KeyRecord {
        id: KeyId {
            scope: huge_scope,
            name,
        },
        parent: Some(root_id),
        class: KeyClass::ClassC,
        wrapped: &a,
    }));
    calls();
    assert_eq!(
        KeyGraph::validate(
            huge_scope,
            &records,
            InputCompleteness::Complete,
            root_id,
            HierarchyLimits::default()
        )
        .unwrap_err(),
        HierarchyError::LimitExceeded
    );
    assert_eq!(calls(), 0);
    let mut overflowing = usize::MAX;
    assert_eq!(
        HierarchyLimits::default().add(&mut overflowing, 1),
        Err(HierarchyError::LimitExceeded)
    );
}

#[test]
fn query_identifiers_are_bounded_before_comparison_or_crypto() {
    let a = fixture("self");
    let records = [record("root", None, KeyClass::Tlk, &a)];
    let graph = graph(&records).unwrap();
    let long = "s".repeat(1025);
    let mut anchor = anchor();
    for (name, error) in [
        ("", HierarchyError::InvalidIdentifier),
        (long.as_str(), HierarchyError::LimitExceeded),
    ] {
        calls();
        assert_eq!(graph.unwrap_target(&anchor, id(name)).unwrap_err(), error);
        anchor.id = id(name);
        assert_eq!(graph.unwrap_target(&anchor, id("root")).unwrap_err(), error);
        assert_eq!(calls(), 0);
        anchor.id = id("root");
    }
}

#[test]
fn identical_record_names_in_foreign_scope_never_supply_a_parent() {
    let a = fixture("self");
    let root = record("root", None, KeyClass::Tlk, &a);
    for foreign in foreign_scopes() {
        let mut duplicate = root;
        duplicate.id.scope = foreign;
        assert_eq!(
            graph(&[root, duplicate]).unwrap_err(),
            HierarchyError::ScopeMismatch
        );
    }
}

#[test]
fn distinct_duplicates_never_choose_first_or_last_value() {
    let a = fixture("self");
    let root = record("root", None, KeyClass::Tlk, &a);
    for changed in [
        KeyRecord {
            wrapped: &[0; 80],
            ..root
        },
        KeyRecord {
            class: KeyClass::ClassC,
            ..root
        },
        KeyRecord {
            parent: Some(id("missing")),
            ..root
        },
    ] {
        for inputs in [[root, changed], [changed, root]] {
            calls();
            assert_eq!(graph(&inputs).unwrap_err(), HierarchyError::DuplicateRecord);
            assert_eq!(calls(), 0);
        }
    }
}

#[test]
fn deterministic_trees_validate_with_shared_suffixes_in_both_orders() {
    let a = fixture("self");
    let names: Vec<_> = (0..64).map(|i| format!("node-{i}")).collect();
    for divisor in [1, 2, 3, 7, 64] {
        let mut records = vec![record("root", None, KeyClass::Tlk, &a)];
        for i in 0..64 {
            records.push(record(
                &names[i],
                Some(if i == 0 {
                    "root"
                } else {
                    &names[(i - 1) / divisor]
                }),
                KeyClass::Tlk,
                &a,
            ));
        }
        assert!(graph(&records).is_ok());
        records.reverse();
        assert!(graph(&records).is_ok());
    }
}
