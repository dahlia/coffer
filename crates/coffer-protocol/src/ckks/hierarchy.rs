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

//! Bounded, offline key graphs over caller-supplied metadata.
//!
//! [`KeyGraph::validate`](crate::ckks::hierarchy::KeyGraph::validate) checks every input node, including unselected branches.
//! [`KeyGraph::unwrap_target`](crate::ckks::hierarchy::KeyGraph::unwrap_target) then checks one explicit anchor and unwraps only
//! the requested path. Neither operation authenticates metadata, establishes
//! trust, proves collection completeness, or performs I/O. See `CKKS.md` for
//! the supported relationship subset and provenance.

use super::UnwrappingKey;
use core::fmt;
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

/// Caller-supplied CloudKit environment, without an inferred endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Development context.
    Development,
    /// Production context.
    Production,
}

/// Caller-supplied database identity; no database is selected implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    /// Private database context.
    Private,
    /// Shared database context.
    Shared,
    /// Public database context.
    Public,
}

/// Exact, borrowed context for one key graph, with redacted `Debug` output.
///
/// Identifiers are compared without normalization or alias substitution. This
/// is an assertion from the collecting caller, not authenticated CloudKit data.
/// The caller retains ownership and responsibility for wiping its metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyScope<'a> {
    /// Opaque account context assigned by the caller, never an auth token.
    pub account: &'a str,
    /// Exact container identifier.
    pub container: &'a str,
    /// Explicit environment.
    pub environment: Environment,
    /// Explicit database.
    pub database: Database,
    /// Exact zone owner; default-owner aliases are not resolved here.
    pub zone_owner: &'a str,
    /// Exact zone name.
    pub zone_name: &'a str,
}

/// A borrowed full key identity; its identifiers are redacted in `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyId<'a> {
    /// Full scope, retained even on parent references.
    pub scope: KeyScope<'a>,
    /// Exact record name; a UUID representation is not required.
    pub name: &'a str,
}

/// Claimed record class, not authenticated metadata or Linux lock protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// Top-level key, including a historical TLK wrapped by another TLK.
    Tlk,
    /// Claimed Class A key.
    ClassA,
    /// Claimed Class C key.
    ClassC,
}

impl TryFrom<&str> for KeyClass {
    type Error = HierarchyError;

    /// Accepts only the three exact published class literals.
    /// Unknown values return [`HierarchyError::UnsupportedClass`].
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "tlk" => Ok(Self::Tlk),
            "classA" => Ok(Self::ClassA),
            "classC" => Ok(Self::ClassC),
            _ => Err(HierarchyError::UnsupportedClass),
        }
    }
}

/// Borrowed typed input for a single key record, not a wire decoder.
///
/// Validation checks all lengths before allocating graph storage. The caller's
/// input buffers are never copied or modified; they remain borrowed for the
/// graph's lifetime. An adapter must reject malformed/duplicate wire fields
/// before constructing this value, and bound its own input allocations.
#[derive(Clone, Copy)]
pub struct KeyRecord<'a> {
    /// Exact full record identity.
    pub id: KeyId<'a>,
    /// Claimed class; only the limited TLK-parent subset is supported.
    pub class: KeyClass,
    /// A complete reference, or true absence. Never map malformed data to `None`.
    pub parent: Option<KeyId<'a>>,
    /// Tag followed by ciphertext, required to be exactly 80 bytes.
    pub wrapped: &'a [u8],
}

/// Explicit collection status asserted by the caller, not proven by this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputCompleteness {
    /// The caller asserts the entire intended key set is supplied.
    Complete,
    /// A partial collection; graph validation always refuses this value.
    Incomplete,
}

/// Positive local resource limits, at or below the hard caps in [`Self::new`].
///
/// Defaults equal the hard caps. These are Coffer policies, not Apple constants.
/// Graph allocations are bounded by node count; metadata is borrowed, not owned.
#[derive(Debug, Clone, Copy)]
pub struct HierarchyLimits {
    nodes: usize,
    identifier_bytes: usize,
    input_bytes: usize,
    depth: usize,
}

impl HierarchyLimits {
    /// Sets positive limits for nodes, each identifier, aggregate input bytes,
    /// and parent edges from any node to the selected anchor.
    ///
    /// Hard caps are 1,024 nodes, 1,024 bytes per identifier, 8 MiB aggregate,
    /// and 64 edges. One unwrap call makes at most `depth + 1` crypto attempts,
    /// including the anchor self-check, and stops at the first failure.
    ///
    /// Aggregate input counts every supplied identifier occurrence (including
    /// repeated scopes and parent IDs), two bytes per scope for its enums,
    /// 80 wrapped bytes and two class/parent discriminator bytes per record.
    /// The separate scope and selected anchor ID also count. Pointer/index
    /// overhead is independently bounded by the node cap. Per-call anchor and
    /// target IDs must meet the identifier limit and exactly match the graph.
    ///
    /// # Errors
    /// Returns [`HierarchyError::InvalidLimits`] for zero or above-cap values.
    pub fn new(
        nodes: usize,
        identifier_bytes: usize,
        input_bytes: usize,
        depth: usize,
    ) -> Result<Self, HierarchyError> {
        if nodes == 0
            || nodes > 1024
            || identifier_bytes == 0
            || identifier_bytes > 1024
            || input_bytes == 0
            || input_bytes > 8 * 1024 * 1024
            || depth == 0
            || depth > 64
        {
            return Err(HierarchyError::InvalidLimits);
        }
        Ok(Self {
            nodes,
            identifier_bytes,
            input_bytes,
            depth,
        })
    }

    fn add(self, total: &mut usize, bytes: usize) -> Result<(), HierarchyError> {
        *total = total
            .checked_add(bytes)
            .ok_or(HierarchyError::LimitExceeded)?;
        if *total > self.input_bytes {
            return Err(HierarchyError::LimitExceeded);
        }
        Ok(())
    }

    fn identifier(self, value: &str, total: &mut usize) -> Result<(), HierarchyError> {
        if value.is_empty() {
            return Err(HierarchyError::InvalidIdentifier);
        }
        if value.len() > self.identifier_bytes {
            return Err(HierarchyError::LimitExceeded);
        }
        self.add(total, value.len())
    }

    fn scope(self, scope: KeyScope<'_>, total: &mut usize) -> Result<(), HierarchyError> {
        for value in [
            scope.account,
            scope.container,
            scope.zone_owner,
            scope.zone_name,
        ] {
            self.identifier(value, total)?;
        }
        self.add(total, 2)
    }

    fn id(self, id: KeyId<'_>, total: &mut usize) -> Result<(), HierarchyError> {
        self.scope(id.scope, total)?;
        self.identifier(id.name, total)
    }
}

impl Default for HierarchyLimits {
    fn default() -> Self {
        Self {
            nodes: 1024,
            identifier_bytes: 1024,
            input_bytes: 8 * 1024 * 1024,
            depth: 64,
        }
    }
}

/// One caller-selected anchor binding and an owned, zeroizing key.
///
/// The caller must independently obtain and authorize this key for the full ID.
/// Construction and a successful self-wrap check do not establish that trust.
/// No cloning, serialization, key search, or fallback is provided.
pub struct AnchorInput<'a> {
    /// Exact binding of the supplied candidate to the selected TLK record.
    pub id: KeyId<'a>,
    /// Candidate key, wiped on drop using the existing primitive's storage.
    pub key: UnwrappingKey,
}

/// Immutable structure checked across the entire supplied key set.
///
/// This type proves only internal consistency under the supported subset.
/// Ciphertext on unselected branches is not authenticated. All metadata stays
/// borrowed and immutable; no graph handle can be used to bypass validation.
///
/// Changing the input while its graph is in use is rejected by the borrow checker:
///
/// ```compile_fail
/// use coffer_protocol::ckks::hierarchy::*;
/// fn invalid<'a>(scope: KeyScope<'a>, records: &mut [KeyRecord<'a>], root: KeyId<'a>) {
///     let graph = KeyGraph::validate(scope, records, InputCompleteness::Complete,
///                                    root, HierarchyLimits::default()).unwrap();
///     records[0].parent = None;
///     drop(graph);
/// }
/// ```
pub struct KeyGraph<'a> {
    scope: KeyScope<'a>,
    records: &'a [KeyRecord<'a>],
    index: BTreeMap<&'a str, usize>,
    parents: Vec<usize>,
    anchor: usize,
    limits: HierarchyLimits,
}

impl<'a> KeyGraph<'a> {
    /// Checks a complete key set in one exact scope before any cryptography.
    ///
    /// Every node must reach the selected self/absent-parent TLK. All other
    /// edges must have a TLK parent, including historical TLK-to-TLK edges.
    /// Validation is iterative with cached depths, bounded storage and no I/O.
    /// It neither proves input completeness nor authenticates metadata/trust.
    ///
    /// This example uses already collected, bounded inputs:
    ///
    /// ```
    /// use coffer_protocol::ckks::hierarchy::*;
    /// fn offline_example(
    ///     scope: KeyScope<'_>, records: &[KeyRecord<'_>],
    ///     anchor: &AnchorInput<'_>, target: KeyId<'_>,
    /// ) -> Result<(), HierarchyError> {
    ///     let graph = KeyGraph::validate(scope, records, InputCompleteness::Complete,
    ///                                    anchor.id, HierarchyLimits::default())?;
    ///     let key = graph.unwrap_target(anchor, target)?;
    ///     // Use key.expose_secret() only for the next explicit offline operation.
    ///     drop(key);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns a fixed [`HierarchyError`] for incomplete/empty input, limits,
    /// malformed identifiers/wrapped lengths, foreign scopes, duplicate IDs,
    /// absent parents/anchor, unsupported roots/relationships, cycles or depth.
    /// Invalid selected-anchor binding/shape is rejected even inside a cycle.
    pub fn validate(
        scope: KeyScope<'a>,
        records: &'a [KeyRecord<'a>],
        completeness: InputCompleteness,
        selected_anchor: KeyId<'_>,
        limits: HierarchyLimits,
    ) -> Result<Self, HierarchyError> {
        if completeness != InputCompleteness::Complete {
            return Err(HierarchyError::IncompleteInput);
        }
        if records.is_empty() {
            return Err(HierarchyError::EmptyInput);
        }
        if records.len() > limits.nodes {
            return Err(HierarchyError::LimitExceeded);
        }

        // All count/length/aggregate checks precede any input-dependent allocation
        // or identifier comparison. No metadata buffers are allocated or copied.
        let mut total = 0;
        limits.scope(scope, &mut total)?;
        limits.id(selected_anchor, &mut total)?;
        for record in records {
            limits.id(record.id, &mut total)?;
            if let Some(parent) = record.parent {
                limits.id(parent, &mut total)?;
            }
            if record.wrapped.len() != 80 {
                return Err(HierarchyError::InvalidWrappedLength);
            }
            limits.add(&mut total, 82)?;
        }
        if selected_anchor.scope != scope {
            return Err(HierarchyError::AnchorBindingMismatch);
        }
        for record in records {
            if record.id.scope != scope || record.parent.is_some_and(|parent| parent.scope != scope)
            {
                return Err(HierarchyError::ScopeMismatch);
            }
        }
        let mut index = BTreeMap::new();
        for (ordinal, record) in records.iter().enumerate() {
            // Exact scope equality was checked for every full ID above.
            if index.insert(record.id.name, ordinal).is_some() {
                return Err(HierarchyError::DuplicateRecord);
            }
        }
        let anchor = *index
            .get(selected_anchor.name)
            .ok_or(HierarchyError::MissingAnchor)?;
        let root = &records[anchor];
        if root.class != KeyClass::Tlk || root.parent.is_some_and(|parent| parent != root.id) {
            return Err(HierarchyError::AnchorNotSelfWrapped);
        }
        let mut parents = Vec::with_capacity(records.len());
        for (ordinal, record) in records.iter().enumerate() {
            if ordinal == anchor {
                parents.push(anchor);
                continue;
            }
            if record.parent.is_none_or(|parent| parent == record.id) {
                return Err(if record.class == KeyClass::Tlk {
                    HierarchyError::MultipleRoots
                } else {
                    HierarchyError::UnsupportedRelationship
                });
            }
            // Absence/self cases were classified above, without dropping scope.
            let parent = record.parent.ok_or(HierarchyError::MissingParent)?;
            let parent = *index
                .get(parent.name)
                .ok_or(HierarchyError::MissingParent)?;
            if records[parent].class != KeyClass::Tlk {
                return Err(HierarchyError::UnsupportedRelationship);
            }
            parents.push(parent);
        }
        // Each node has one parent. Mark the sole permitted terminal as done;
        // every completed suffix therefore reaches that exact anchor. A shared
        // parent is a cached suffix, not a cycle. Never recurse on input data.
        let mut states = vec![0u8; records.len()];
        let mut depths = vec![0usize; records.len()];
        let mut path = Vec::with_capacity(limits.depth.min(records.len()));
        states[anchor] = 2;
        for start in 0..records.len() {
            let mut node = start;
            while states[node] != 2 {
                if states[node] == 1 {
                    return Err(HierarchyError::Cycle);
                }
                if path.len() == limits.depth {
                    return Err(HierarchyError::LimitExceeded);
                }
                states[node] = 1;
                path.push(node);
                node = parents[node];
            }
            let mut depth = depths[node];
            while let Some(node) = path.pop() {
                depth = depth.checked_add(1).ok_or(HierarchyError::LimitExceeded)?;
                if depth > limits.depth {
                    return Err(HierarchyError::LimitExceeded);
                }
                depths[node] = depth;
                states[node] = 2;
            }
        }
        Ok(Self {
            scope,
            records,
            index,
            parents,
            anchor,
            limits,
        })
    }

    /// Checks one explicit anchor and unwraps only the requested target path.
    ///
    /// The anchor record is unwrapped once and compared to the candidate using
    /// `subtle` on fixed 64-byte slices. Only then are path edges unwrapped, once
    /// each. There is no retry, alternate parent, cache, storage, or network path.
    /// Intermediates use zeroizing storage and are dropped as each step completes.
    /// On any failure no partial key is returned. The result borrows the graph
    /// and anchor lifetimes; drop it promptly. Repeated calls have separate budgets.
    ///
    /// Success authenticates only wrapped bytes, not record names, claimed
    /// classes, parent metadata, freshness, completeness, or anchor trust.
    ///
    /// An output cannot survive dropping its anchor:
    ///
    /// ```compile_fail
    /// use coffer_protocol::ckks::hierarchy::{AnchorInput, KeyGraph, KeyId};
    /// fn invalid(graph: &KeyGraph<'_>, anchor: AnchorInput<'_>, target: KeyId<'_>) {
    ///     let result = graph.unwrap_target(&anchor, target).unwrap();
    ///     drop(anchor);
    ///     let _ = result.expose_secret();
    /// }
    /// ```
    ///
    /// Constant-time comparison does not promise side-channel safety for an
    /// arbitrary compiler, debug build, or deployment environment.
    ///
    /// # Errors
    /// Returns fixed errors for invalid/oversized identifiers, anchor binding
    /// mismatch, foreign/unknown target, anchor equality mismatch, or wrapped-key
    /// authentication failure. Binding/target checks precede all crypto calls.
    pub fn unwrap_target<'g>(
        &'g self,
        anchor: &'g AnchorInput<'_>,
        target: KeyId<'_>,
    ) -> Result<ResolvedKey<'g>, HierarchyError> {
        self.limits.id(anchor.id, &mut 0)?;
        self.limits.id(target, &mut 0)?;
        if anchor.id != self.records[self.anchor].id {
            return Err(HierarchyError::AnchorBindingMismatch);
        }
        if target.scope != self.scope {
            return Err(HierarchyError::ScopeMismatch);
        }
        let target = *self
            .index
            .get(target.name)
            .ok_or(HierarchyError::UnknownTarget)?;
        let checked_anchor = unwrap(&anchor.key, self.records[self.anchor].wrapped)?;
        if !bool::from(
            checked_anchor
                .expose_secret()
                .as_slice()
                .ct_eq(anchor.key.expose_secret().as_slice()),
        ) {
            return Err(HierarchyError::AnchorKeyMismatch);
        }
        // Only bounded indices are retained. At most two temporary plaintext
        // keys coexist during a step; replacing `current` wipes its old value.
        let mut path = Vec::with_capacity(self.limits.depth.min(self.records.len()));
        let mut node = target;
        for _ in 0..self.limits.depth {
            if node == self.anchor {
                break;
            }
            path.push(node);
            node = self.parents[node];
        }
        // Validation proves this condition; retain a fail-closed check locally.
        if node != self.anchor {
            return Err(HierarchyError::LimitExceeded);
        }
        let mut current = checked_anchor;
        for node in path.into_iter().rev() {
            current = unwrap(&current, self.records[node].wrapped)?;
        }
        Ok(ResolvedKey {
            id: self.records[target].id,
            class: self.records[target].class,
            key: current,
        })
    }
}

/// A selected key in zeroizing storage, borrowing graph/anchor lifetimes.
///
/// The full identity and class remain caller claims. No owned raw-key escape,
/// cloning or serialization is provided. Drop promptly after offline use.
pub struct ResolvedKey<'a> {
    id: KeyId<'a>,
    class: KeyClass,
    key: UnwrappingKey,
}

impl ResolvedKey<'_> {
    /// Returns the full claimed binding; never log its individual identifiers.
    #[must_use]
    pub fn id(&self) -> KeyId<'_> {
        self.id
    }

    /// Returns the structurally checked, unauthenticated class claim.
    #[must_use]
    pub fn class(&self) -> KeyClass {
        self.class
    }

    /// Explicitly borrows key bytes for the caller's next offline operation.
    /// Never log or persist these bytes without appropriate protection.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 64] {
        self.key.expose_secret()
    }
}

/// Fixed, secret-free failures for graph validation and selected-path unwrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyError {
    /// The caller has not supplied a complete collection.
    IncompleteInput,
    /// No records were supplied.
    EmptyInput,
    /// A limit was zero or exceeded its hard cap.
    InvalidLimits,
    /// A count, identifier, aggregate byte count or depth exceeded its limit.
    LimitExceeded,
    /// An identifier was empty.
    InvalidIdentifier,
    /// Wrapped input was not exactly 80 bytes.
    InvalidWrappedLength,
    /// A record ID occurred more than once, even with identical contents.
    DuplicateRecord,
    /// A node, parent, or target did not have the exact graph scope.
    ScopeMismatch,
    /// A referenced parent was absent from the complete input.
    MissingParent,
    /// A nonterminal parent cycle was present.
    Cycle,
    /// An unknown class literal was supplied during typed conversion.
    UnsupportedClass,
    /// A class/parent relationship was outside the supported TLK-parent subset.
    UnsupportedRelationship,
    /// Another root was present; this API supports exactly one anchor.
    MultipleRoots,
    /// The selected anchor record was absent from the input.
    MissingAnchor,
    /// The selected or supplied anchor had a different full binding.
    AnchorBindingMismatch,
    /// The selected anchor was not a self/absent-parent TLK.
    AnchorNotSelfWrapped,
    /// Valid anchor ciphertext unwrapped to a key different from the candidate.
    AnchorKeyMismatch,
    /// Anchor or selected-path ciphertext failed authentication.
    KeyAuthenticationFailed,
    /// No record matched the explicitly selected target.
    UnknownTarget,
}

impl fmt::Display for HierarchyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IncompleteInput => "incomplete CKKS key input",
            Self::EmptyInput => "empty CKKS key input",
            Self::InvalidLimits => "invalid CKKS graph limits",
            Self::LimitExceeded => "CKKS graph limit exceeded",
            Self::InvalidIdentifier => "invalid CKKS identifier",
            Self::InvalidWrappedLength => "invalid CKKS wrapped-key length",
            Self::DuplicateRecord => "duplicate CKKS key record",
            Self::ScopeMismatch => "CKKS scope mismatch",
            Self::MissingParent => "missing CKKS parent",
            Self::Cycle => "CKKS key cycle",
            Self::UnsupportedClass => "unsupported CKKS key class",
            Self::UnsupportedRelationship => "unsupported CKKS key relationship",
            Self::MultipleRoots => "multiple CKKS roots are unsupported",
            Self::MissingAnchor => "missing CKKS anchor record",
            Self::AnchorBindingMismatch => "CKKS anchor binding mismatch",
            Self::AnchorNotSelfWrapped => "CKKS anchor is not a self-wrapped TLK",
            Self::AnchorKeyMismatch => "CKKS anchor key mismatch",
            Self::KeyAuthenticationFailed => "CKKS key authentication failed",
            Self::UnknownTarget => "unknown CKKS target",
        })
    }
}
impl std::error::Error for HierarchyError {}

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$ (
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    )+};
}
redacted_debug!(
    KeyScope,
    KeyId,
    KeyRecord,
    AnchorInput,
    KeyGraph,
    ResolvedKey
);

fn unwrap(key: &UnwrappingKey, wrapped: &[u8]) -> Result<UnwrappingKey, HierarchyError> {
    #[cfg(test)]
    UNWRAP_CALLS.with(|n| n.set(n.get() + 1));
    key.unwrap_key(wrapped)
        .map_err(|_| HierarchyError::KeyAuthenticationFailed)
}

#[cfg(test)]
std::thread_local! { static UNWRAP_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
mod tests;
