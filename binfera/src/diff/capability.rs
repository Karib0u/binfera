//! What a sample gained and lost at the level of capa rules.
//!
//! Rule matches come from capability recovery and functions from native recovery, whose function
//! starts can differ. A match is therefore tied to the function containing its address, and one
//! that lies in no known function is counted as unmapped instead of being guessed at.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{Fingerprint, FunctionMatch};
use crate::rd::{AddressValue, Metadata, RdAddress, ResultDocument, RuleMatches};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSummary {
    pub name: String,
    pub namespace: Option<String>,
    pub scope: String,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub addresses: Vec<u64>,
    /// The functions those addresses lie in, to open them from the rule.
    pub functions: Vec<u64>,
}

/// A rule both samples match, at code that is not the same once functions are paired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetargetedRule {
    pub name: String,
    pub namespace: Option<String>,
    /// Matches in functions of A whose counterpart in B no longer matches.
    pub lost: Vec<u64>,
    /// Matches in functions of B whose counterpart in A did not match.
    pub gained: Vec<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDelta {
    pub added: Vec<RuleSummary>,
    pub removed: Vec<RuleSummary>,
    pub retargeted: Vec<RetargetedRule>,
    pub unchanged: usize,
    /// Matches that lie outside every recovered function, so could not be followed.
    pub unmapped: usize,
    pub attack_added: Vec<String>,
    pub attack_removed: Vec<String>,
    pub similarity: Option<f64>,
}

impl CapabilityDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.retargeted.is_empty()
    }
}

fn absolute(address: &RdAddress) -> Option<u64> {
    match &address.value {
        Some(AddressValue::Int(value)) if address.kind != "no address" => Some(*value),
        Some(AddressValue::Tuple(parts)) => parts.first().copied(),
        _ => None,
    }
}

/// Library code and rules that only exist to feed other rules say nothing about the sample.
fn reported(document: &ResultDocument) -> BTreeMap<&str, &RuleMatches> {
    document
        .rules
        .iter()
        .filter(|(_, rule)| !rule.meta.lib && !rule.meta.is_subscope_rule)
        .map(|(name, rule)| (name.as_str(), rule))
        .collect()
}

fn scope_of(rule: &RuleMatches) -> String {
    rule.meta
        .scopes
        .static_
        .clone()
        .unwrap_or_else(|| "dynamic".to_string())
}

fn rule_summary(rule: &RuleMatches, owners: &Owners) -> RuleSummary {
    let mut addresses: Vec<u64> = rule
        .matches
        .iter()
        .filter_map(|(address, _)| absolute(address))
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    RuleSummary {
        name: rule.meta.name.clone(),
        namespace: rule.meta.namespace.clone(),
        scope: scope_of(rule),
        attack: rule
            .meta
            .attack
            .iter()
            .map(|spec| spec.id.clone())
            .collect(),
        mbc: rule.meta.mbc.iter().map(|spec| spec.id.clone()).collect(),
        functions: functions_of(rule, owners, &mut 0).into_iter().collect(),
        addresses,
    }
}

/// The start of the function containing an address, from each function's extent.
struct Owners(BTreeMap<u64, (u64, u64)>);

impl Owners {
    fn new(print: &Fingerprint) -> Owners {
        let starts: Vec<u64> = print.functions.iter().map(|f| f.address).collect();
        Owners(
            print
                .functions
                .iter()
                .enumerate()
                .map(|(index, function)| {
                    // A match is at a function, block or instruction, which lies before the next
                    // function's start unless the function's own blocks are scattered.
                    let end = starts.get(index + 1).copied().unwrap_or(u64::MAX);
                    (function.address, (function.address, end))
                })
                .collect(),
        )
    }

    fn of(&self, address: u64) -> Option<u64> {
        let (_, (start, end)) = self.0.range(..=address).next_back()?;
        (address < *end).then_some(*start)
    }
}

fn functions_of(rule: &RuleMatches, owners: &Owners, unmapped: &mut usize) -> BTreeSet<u64> {
    let mut found = BTreeSet::new();
    if scope_of(rule) == "file" {
        return found;
    }
    for (address, _) in &rule.matches {
        match absolute(address).and_then(|value| owners.of(value)) {
            Some(owner) => {
                found.insert(owner);
            }
            None => *unmapped += 1,
        }
    }
    found
}

/// Version, rule sources and extractor: what must agree for a delta to mean the samples differ.
fn provenance(document: &ResultDocument) -> (&str, &[String], &str) {
    match &document.meta {
        Metadata::Static {
            version, analysis, ..
        } => (version, &analysis.rules, &analysis.extractor),
        Metadata::Dynamic {
            version, analysis, ..
        } => (version, &analysis.rules, &analysis.extractor),
    }
}

fn guard(left: &ResultDocument, right: &ResultDocument, warnings: &mut Vec<String>) {
    let (version_a, rules_a, extractor_a) = provenance(left);
    let (version_b, rules_b, extractor_b) = provenance(right);
    if version_a != version_b {
        warnings.push(format!(
            "capabilities came from different binfera versions ({version_a} and {version_b})"
        ));
    }
    if rules_a != rules_b {
        warnings.push(
            "capabilities came from different rule directories, so a rule update can look like new behaviour"
                .to_string(),
        );
    }
    if extractor_a != extractor_b {
        warnings.push(format!(
            "capabilities came from different extractors ({extractor_a} and {extractor_b})"
        ));
    }
}

/// The rules matching in each function, by the function's address.
fn rules_by_function<'a>(
    rules: &BTreeMap<&'a str, &RuleMatches>,
    owners: &Owners,
) -> BTreeMap<u64, Vec<&'a str>> {
    let mut found: BTreeMap<u64, Vec<&'a str>> = BTreeMap::new();
    for (name, rule) in rules {
        for function in functions_of(rule, owners, &mut 0) {
            found.entry(function).or_default().push(name);
        }
    }
    found
}

/// Says on each function which rules match in it.
pub(super) fn attach(
    left: &ResultDocument,
    right: &ResultDocument,
    a: &Fingerprint,
    b: &Fingerprint,
    outcome: &mut super::matcher::Outcome,
) {
    let (rules_a, rules_b) = (reported(left), reported(right));
    let in_a = rules_by_function(&rules_a, &Owners::new(a));
    let in_b = rules_by_function(&rules_b, &Owners::new(b));
    for found in &mut outcome.matches {
        let empty = Vec::new();
        let here_a = in_a.get(&found.a_addr).unwrap_or(&empty);
        let here_b = in_b.get(&found.b_addr).unwrap_or(&empty);
        let names = |list: &[&str], other: &[&str], keep: bool| -> Vec<String> {
            list.iter()
                .filter(|name| other.contains(name) == keep)
                .map(|name| name.to_string())
                .collect()
        };
        found.evidence.rules_only_a = names(here_a, here_b, false);
        found.evidence.rules_only_b = names(here_b, here_a, false);
        found.evidence.rules_both = names(here_a, here_b, true);
    }
    for (list, rules) in [
        (&mut outcome.unmatched_a, &in_a),
        (&mut outcome.unmatched_b, &in_b),
    ] {
        for function in list.iter_mut() {
            if let Some(names) = rules.get(&function.address) {
                function.rules = names.iter().map(|name| name.to_string()).collect();
            }
        }
    }
}

pub(super) fn compare(
    left: &ResultDocument,
    right: &ResultDocument,
    a: &Fingerprint,
    b: &Fingerprint,
    matches: &[FunctionMatch],
    warnings: &mut Vec<String>,
) -> CapabilityDelta {
    guard(left, right, warnings);
    let (rules_a, rules_b) = (reported(left), reported(right));
    let (owners_a, owners_b) = (Owners::new(a), Owners::new(b));
    let forward: BTreeMap<u64, u64> = matches.iter().map(|m| (m.a_addr, m.b_addr)).collect();
    let backward: BTreeMap<u64, u64> = matches.iter().map(|m| (m.b_addr, m.a_addr)).collect();
    let mut delta = CapabilityDelta::default();
    for (name, rule) in &rules_a {
        let Some(other) = rules_b.get(name) else {
            delta.removed.push(rule_summary(rule, &owners_a));
            continue;
        };
        let in_a = functions_of(rule, &owners_a, &mut delta.unmapped);
        let in_b = functions_of(other, &owners_b, &mut delta.unmapped);
        // Only pairs say anything: a function with no counterpart is already reported as added or
        // removed, and a rule that matches there as well as elsewhere has not moved.
        let lost: Vec<u64> = in_a
            .iter()
            .filter(|at| forward.get(at).is_some_and(|peer| !in_b.contains(peer)))
            .copied()
            .collect();
        let gained: Vec<u64> = in_b
            .iter()
            .filter(|at| backward.get(at).is_some_and(|peer| !in_a.contains(peer)))
            .copied()
            .collect();
        if lost.is_empty() && gained.is_empty() {
            delta.unchanged += 1;
        } else {
            delta.retargeted.push(RetargetedRule {
                name: rule.meta.name.clone(),
                namespace: rule.meta.namespace.clone(),
                lost,
                gained,
            });
        }
    }
    delta.added = rules_b
        .iter()
        .filter(|(name, _)| !rules_a.contains_key(*name))
        .map(|(_, rule)| rule_summary(rule, &owners_b))
        .collect();
    let techniques = |rules: &BTreeMap<&str, &RuleMatches>| {
        rules
            .values()
            .flat_map(|rule| rule.meta.attack.iter().map(|spec| spec.id.clone()))
            .collect::<BTreeSet<_>>()
    };
    let (attack_a, attack_b) = (techniques(&rules_a), techniques(&rules_b));
    delta.attack_added = attack_b.difference(&attack_a).cloned().collect();
    delta.attack_removed = attack_a.difference(&attack_b).cloned().collect();
    let names_a: Vec<&str> = rules_a.keys().copied().collect();
    let names_b: Vec<&str> = rules_b.keys().copied().collect();
    delta.similarity = super::jaccard(&names_a, &names_b);
    if a.header.packed.is_some() != b.header.packed.is_some() {
        warnings.push(
            "only one file looks packed, so most of the capability delta is probably packing"
                .to_string(),
        );
    }
    delta
}
