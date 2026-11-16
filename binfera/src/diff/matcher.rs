//! Pair the functions of two binaries.
//!
//! Passes run from most to least certain, and each only considers what the earlier ones left:
//! unique content, unique shape, confirmed names, then the call graph and scored candidates in
//! turn until nothing moves. A pair is accepted only when each side is the other's clear best;
//! anything ambiguous stays unmatched rather than being settled by order. The same inputs always
//! give the same pairs: there is no hashing order or thread scheduling here to leak through.
use std::collections::{BTreeMap, BTreeSet};

use super::fingerprint::{FunctionRecord, Ref, MINHASH_SLOTS};
use super::{ChangeReason, Evidence, FunctionMatch, FunctionRef, Method, Signal};

/// Below this many instructions a function matches too much else to be evidence of itself.
const SMALL_FUNCTION: u32 = 4;
const NAME_THRESHOLD: f64 = 0.25;
const PROPAGATE_THRESHOLD: f64 = 0.45;
const FUZZY_THRESHOLD: f64 = 0.55;
/// How far a best candidate must beat the next one to be believed.
const MARGIN: f64 = 0.03;
const MAX_ROUNDS: usize = 8;
const MINHASH_BANDS: usize = 8;
/// A key shared by more functions than this describes a family, not a function.
const MAX_BUCKET: usize = 32;
/// Candidates scored per function, which keeps the cost near linear.
const CANDIDATE_BUDGET: usize = 24;
/// Neighbours considered around one pair, on each side.
const MAX_NEIGHBOURS: usize = 64;
/// Enough differing strings and constants to see what changed in a function that changed a lot.
const MAX_LISTED: usize = 64;

pub(super) struct Outcome {
    pub matches: Vec<FunctionMatch>,
    pub unmatched_a: Vec<FunctionRef>,
    pub unmatched_b: Vec<FunctionRef>,
}

fn function_ref(function: &FunctionRecord) -> FunctionRef {
    let features = Features::new(function);
    FunctionRef {
        address: function.address,
        name: function.display.clone().or_else(|| function.name.clone()),
        instructions: function.instructions,
        strings: features.strings.into_iter().take(MAX_LISTED).collect(),
        imports: features.apis.into_iter().take(MAX_LISTED).collect(),
        rules: Vec::new(),
    }
}

impl Outcome {
    pub(super) fn unmatched(a: &[FunctionRecord], b: &[FunctionRecord]) -> Outcome {
        Outcome {
            matches: Vec::new(),
            unmatched_a: a.iter().map(function_ref).collect(),
            unmatched_b: b.iter().map(function_ref).collect(),
        }
    }
}

/// One side's call graph, as positions in its function list.
struct Graph {
    callees: Vec<Vec<usize>>,
    callers: Vec<Vec<usize>>,
}

impl Graph {
    fn new(functions: &[FunctionRecord]) -> Graph {
        let index: BTreeMap<u64, usize> = functions
            .iter()
            .enumerate()
            .map(|(position, function)| (function.address, position))
            .collect();
        let mut callees = vec![Vec::new(); functions.len()];
        let mut callers = vec![Vec::new(); functions.len()];
        for (from, function) in functions.iter().enumerate() {
            let mut seen = BTreeSet::new();
            for reference in &function.refs {
                let Ref::Call(target) = reference else {
                    continue;
                };
                let Some(to) = index.get(target).copied() else {
                    continue;
                };
                if seen.insert(to) {
                    if let Some(list) = callees.get_mut(from) {
                        list.push(to);
                    }
                    if let Some(list) = callers.get_mut(to) {
                        list.push(from);
                    }
                }
            }
        }
        Graph { callees, callers }
    }
}

struct Features {
    apis: Vec<String>,
    strings: Vec<String>,
}

impl Features {
    fn new(function: &FunctionRecord) -> Features {
        let mut apis = Vec::new();
        let mut strings = Vec::new();
        for reference in &function.refs {
            match reference {
                Ref::Api(name) => apis.push(name.clone()),
                Ref::Str(text) => strings.push(text.clone()),
                Ref::Call(_) => {}
            }
        }
        apis.sort();
        apis.dedup();
        strings.sort();
        strings.dedup();
        Features { apis, strings }
    }
}

fn ratio(a: f64, b: f64) -> f64 {
    let largest = a.max(b);
    if largest == 0.0 {
        1.0
    } else {
        a.min(b) / largest
    }
}

fn minhash_estimate(a: &[u32], b: &[u32]) -> f64 {
    let same = a.iter().zip(b).filter(|(x, y)| x == y).count();
    same as f64 / MINHASH_SLOTS as f64
}

struct Matcher<'a> {
    a: &'a [FunctionRecord],
    b: &'a [FunctionRecord],
    features_a: Vec<Features>,
    features_b: Vec<Features>,
    graph_a: Graph,
    graph_b: Graph,
    a_to_b: Vec<Option<usize>>,
    b_to_a: Vec<Option<usize>>,
    found: BTreeMap<usize, (usize, Method, f64)>,
}

impl Matcher<'_> {
    fn free_a(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.a.len()).filter(|at| matches!(self.a_to_b.get(*at), Some(None)))
    }

    fn free_b(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.b.len()).filter(|at| matches!(self.b_to_a.get(*at), Some(None)))
    }

    fn is_free_a(&self, at: usize) -> bool {
        matches!(self.a_to_b.get(at), Some(None))
    }

    fn is_free_b(&self, at: usize) -> bool {
        matches!(self.b_to_a.get(at), Some(None))
    }

    fn accept(&mut self, a: usize, b: usize, method: Method, confidence: f64) -> bool {
        if !self.is_free_a(a) || !self.is_free_b(b) {
            return false;
        }
        if let Some(slot) = self.a_to_b.get_mut(a) {
            *slot = Some(b);
        }
        if let Some(slot) = self.b_to_a.get_mut(b) {
            *slot = Some(a);
        }
        self.found
            .insert(a, (b, method, confidence.clamp(0.0, 1.0)));
        true
    }

    /// How much of each side's call graph already agrees with this pairing; `None` with no
    /// neighbours to judge by.
    fn context(&self, a: usize, b: usize) -> Option<f64> {
        let side = |near_a: &[usize], near_b: &[usize]| -> (usize, usize) {
            let wanted: BTreeSet<usize> = near_b.iter().copied().collect();
            let agreeing = near_a
                .iter()
                .filter(|at| {
                    self.a_to_b
                        .get(**at)
                        .copied()
                        .flatten()
                        .is_some_and(|peer| wanted.contains(&peer))
                })
                .count();
            (agreeing, near_a.len().max(near_b.len()))
        };
        let empty = Vec::new();
        let (calls, call_total) = side(
            self.graph_a.callees.get(a).unwrap_or(&empty),
            self.graph_b.callees.get(b).unwrap_or(&empty),
        );
        let (called, called_total) = side(
            self.graph_a.callers.get(a).unwrap_or(&empty),
            self.graph_b.callers.get(b).unwrap_or(&empty),
        );
        let total = call_total + called_total;
        (total > 0).then(|| (calls + called) as f64 / total as f64)
    }

    /// Each thing a pair's score weighs, leaving out what neither function has: a pair is not
    /// marked down because neither calls an import.
    fn signals(&self, a: usize, b: usize) -> Vec<Signal> {
        let (Some(left), Some(right), Some(features_a), Some(features_b)) = (
            self.a.get(a),
            self.b.get(b),
            self.features_a.get(a),
            self.features_b.get(b),
        ) else {
            return Vec::new();
        };
        let shape = if left.cfg == right.cfg {
            1.0
        } else {
            (ratio(f64::from(left.blocks), f64::from(right.blocks))
                + ratio(f64::from(left.edges), f64::from(right.edges)))
                / 2.0
        };
        [
            (
                "imports",
                super::jaccard(&features_a.apis, &features_b.apis),
                3.0,
            ),
            (
                "strings",
                super::jaccard(&features_a.strings, &features_b.strings),
                3.0,
            ),
            (
                "constants",
                super::jaccard(&left.constants, &right.constants),
                2.0,
            ),
            (
                "instruction patterns",
                Some(minhash_estimate(&left.minhash, &right.minhash)),
                3.0,
            ),
            ("control flow", Some(shape), 2.0),
            (
                "size",
                Some(ratio(
                    f64::from(left.instructions),
                    f64::from(right.instructions),
                )),
                1.0,
            ),
            ("callers and callees", self.context(a, b), 3.0),
        ]
        .into_iter()
        .filter_map(|(name, value, weight)| {
            value.map(|value| Signal {
                name: name.to_string(),
                value,
                weight,
            })
        })
        .collect()
    }

    fn score(&self, a: usize, b: usize) -> f64 {
        let (Some(left), Some(right)) = (self.a.get(a), self.b.get(b)) else {
            return 0.0;
        };
        // Identical functions tie on everything but where they sit in the call graph.
        if left.content == right.content {
            return 0.9 + 0.1 * self.context(a, b).unwrap_or(0.0);
        }
        let signals = self.signals(a, b);
        let weight: f64 = signals.iter().map(|signal| signal.weight).sum();
        if weight == 0.0 {
            return 0.0;
        }
        signals
            .iter()
            .map(|signal| signal.value * signal.weight)
            .sum::<f64>()
            / weight
    }

    /// Small functions are alike by nature, so their score carries less confidence.
    fn confidence(&self, a: usize, b: usize, score: f64) -> f64 {
        let size = |record: Option<&FunctionRecord>| record.map_or(0, |f| f.instructions);
        let smaller = size(self.a.get(a)).min(size(self.b.get(b)));
        score * (0.5 + 0.5 * (f64::from(smaller) / 10.0).min(1.0))
    }

    /// Passes on a hash: a value held by exactly one free function on each side.
    fn unique_hash(
        &mut self,
        method: Method,
        minimum: u32,
        confidence: f64,
        key: impl Fn(&FunctionRecord) -> u64,
    ) {
        let mut left: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for at in self.free_a() {
            if let Some(function) = self.a.get(at).filter(|f| f.instructions >= minimum) {
                left.entry(key(function)).or_default().push(at);
            }
        }
        let mut right: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for at in self.free_b() {
            if let Some(function) = self.b.get(at).filter(|f| f.instructions >= minimum) {
                right.entry(key(function)).or_default().push(at);
            }
        }
        for (hash, ours) in &left {
            if let ([one], Some([other])) = (ours.as_slice(), right.get(hash).map(Vec::as_slice)) {
                let full = self.confidence(*one, *other, 1.0);
                self.accept(*one, *other, method, confidence.min(full.max(0.6)));
            }
        }
    }

    fn names(&mut self) {
        let collect = |functions: &[FunctionRecord], free: Vec<usize>| {
            let mut names: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for at in free {
                if let Some(name) = functions.get(at).and_then(|f| f.name.clone()) {
                    names.entry(name).or_default().push(at);
                }
            }
            names
        };
        let left = collect(self.a, self.free_a().collect());
        let right = collect(self.b, self.free_b().collect());
        for (name, ours) in &left {
            let ([one], Some([other])) = (ours.as_slice(), right.get(name).map(Vec::as_slice))
            else {
                continue;
            };
            let score = self.score(*one, *other);
            let tiny = self
                .a
                .get(*one)
                .is_some_and(|f| f.instructions < SMALL_FUNCTION)
                && self
                    .b
                    .get(*other)
                    .is_some_and(|f| f.instructions < SMALL_FUNCTION);
            // A name can be copied or reused, so it needs some support from the code.
            if score >= NAME_THRESHOLD || tiny {
                self.accept(*one, *other, Method::Name, 0.7 + 0.3 * score);
            }
        }
    }

    /// Accepts pairs where each side is the other's clear best.
    fn accept_mutual(
        &mut self,
        mut scored: Vec<(usize, usize, f64)>,
        method: Method,
        threshold: f64,
    ) -> usize {
        scored.retain(|(a, b, score)| {
            *score >= threshold && self.is_free_a(*a) && self.is_free_b(*b)
        });
        scored.sort_by(|x, y| {
            y.2.total_cmp(&x.2)
                .then_with(|| x.0.cmp(&y.0))
                .then_with(|| x.1.cmp(&y.1))
        });
        let mut best_a: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
        let mut best_b: BTreeMap<usize, (f64, f64, usize)> = BTreeMap::new();
        for (a, b, score) in &scored {
            let note = |map: &mut BTreeMap<usize, (f64, f64, usize)>, key: usize, peer: usize| {
                map.entry(key)
                    .and_modify(|entry| {
                        if peer != entry.2 && entry.1 < *score {
                            entry.1 = *score;
                        }
                    })
                    .or_insert((*score, f64::MIN, peer));
            };
            note(&mut best_a, *a, *b);
            note(&mut best_b, *b, *a);
        }
        let mut accepted = 0;
        for (a, b, score) in scored {
            let clear = |entry: Option<&(f64, f64, usize)>, peer: usize| {
                entry.is_some_and(|(top, second, who)| *who == peer && *top - *second >= MARGIN)
            };
            if clear(best_a.get(&a), b) && clear(best_b.get(&b), a) {
                let confidence = self.confidence(a, b, score);
                accepted += usize::from(self.accept(a, b, method, confidence));
            }
        }
        accepted
    }

    /// Scores the free neighbours of each matched pair against each other.
    fn propagate(&mut self) -> usize {
        let mut scored = BTreeMap::new();
        for (a, b) in self
            .found
            .iter()
            .map(|(a, (b, ..))| (*a, *b))
            .collect::<Vec<_>>()
        {
            let empty = Vec::new();
            for (near_a, near_b) in [
                (
                    self.graph_a.callees.get(a).unwrap_or(&empty),
                    self.graph_b.callees.get(b).unwrap_or(&empty),
                ),
                (
                    self.graph_a.callers.get(a).unwrap_or(&empty),
                    self.graph_b.callers.get(b).unwrap_or(&empty),
                ),
            ] {
                let left: Vec<usize> = near_a
                    .iter()
                    .copied()
                    .filter(|at| self.is_free_a(*at))
                    .take(MAX_NEIGHBOURS)
                    .collect();
                let right: Vec<usize> = near_b
                    .iter()
                    .copied()
                    .filter(|at| self.is_free_b(*at))
                    .take(MAX_NEIGHBOURS)
                    .collect();
                for x in &left {
                    for y in &right {
                        scored.entry((*x, *y)).or_insert_with(|| self.score(*x, *y));
                    }
                }
            }
        }
        let scored = scored.into_iter().map(|((x, y), s)| (x, y, s)).collect();
        self.accept_mutual(scored, Method::Propagated, PROPAGATE_THRESHOLD)
    }

    /// Keys a function by things it shares with few others, to find candidates without trying
    /// every pair.
    fn keys(function: &FunctionRecord, features: &Features) -> Vec<u64> {
        let mut keys = Vec::new();
        for band in function.minhash.chunks(MINHASH_SLOTS / MINHASH_BANDS) {
            let mut hash = super::fingerprint::Fnv::new();
            for value in band {
                hash.number(u64::from(*value));
            }
            hash.bytes(&[keys.len() as u8]);
            keys.push(hash.finish());
        }
        for name in features.apis.iter().chain(&features.strings) {
            keys.push(super::fingerprint::hash_text(name));
        }
        for constant in &function.constants {
            keys.push(
                super::fingerprint::Fnv::new()
                    .bytes(b"k")
                    .number(*constant)
                    .finish(),
            );
        }
        keys.push(
            super::fingerprint::Fnv::new()
                .bytes(b"g")
                .number(function.cfg)
                .finish(),
        );
        keys
    }

    fn fuzzy(&mut self) -> usize {
        let mut buckets_a: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for at in self.free_a() {
            if let (Some(function), Some(features)) = (self.a.get(at), self.features_a.get(at)) {
                for key in Self::keys(function, features) {
                    buckets_a.entry(key).or_default().push(at);
                }
            }
        }
        let mut buckets_b: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for at in self.free_b() {
            if let (Some(function), Some(features)) = (self.b.get(at), self.features_b.get(at)) {
                for key in Self::keys(function, features) {
                    buckets_b.entry(key).or_default().push(at);
                }
            }
        }
        let mut shared: BTreeMap<usize, BTreeMap<usize, u32>> = BTreeMap::new();
        for (key, ours) in &buckets_a {
            let Some(theirs) = buckets_b.get(key) else {
                continue;
            };
            if ours.len() > MAX_BUCKET || theirs.len() > MAX_BUCKET {
                continue;
            }
            for x in ours {
                for y in theirs {
                    *shared.entry(*x).or_default().entry(*y).or_default() += 1;
                }
            }
        }
        let mut scored = Vec::new();
        for (x, peers) in shared {
            let mut peers: Vec<(usize, u32)> = peers.into_iter().collect();
            peers.sort_by(|p, q| q.1.cmp(&p.1).then_with(|| p.0.cmp(&q.0)));
            for (y, _) in peers.into_iter().take(CANDIDATE_BUDGET) {
                scored.push((x, y, self.score(x, y)));
            }
        }
        self.accept_mutual(scored, Method::Fuzzy, FUZZY_THRESHOLD)
    }

    /// Identical functions left over are interchangeable: pairing them by position changes nothing
    /// about what differs, and leaving them out would report changes that are not there.
    fn duplicates(&mut self) {
        let mut left: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for at in self.free_a() {
            if let Some(function) = self.a.get(at) {
                left.entry(function.content).or_default().push(at);
            }
        }
        let mut right: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for at in self.free_b() {
            if let Some(function) = self.b.get(at) {
                right.entry(function.content).or_default().push(at);
            }
        }
        for (hash, ours) in &left {
            for (x, y) in ours.iter().zip(right.get(hash).into_iter().flatten()) {
                self.accept(*x, *y, Method::Duplicate, 0.5);
            }
        }
    }
}

/// What differs within a pair once the callees are known. A call counts as unchanged only when it
/// goes to the match of the old callee, so a redirected call cannot hide behind masked addresses.
fn reasons(
    left: &FunctionRecord,
    right: &FunctionRecord,
    forward: &BTreeMap<u64, u64>,
) -> Vec<ChangeReason> {
    let mut found = BTreeSet::new();
    if left.shape != right.shape {
        found.insert(ChangeReason::Code);
    }
    let pick = |function: &FunctionRecord, want: fn(&Ref) -> bool| -> Vec<Ref> {
        function.refs.iter().filter(|r| want(r)).cloned().collect()
    };
    if pick(left, |r| matches!(r, Ref::Str(_))) != pick(right, |r| matches!(r, Ref::Str(_))) {
        found.insert(ChangeReason::String);
    }
    if pick(left, |r| matches!(r, Ref::Api(_))) != pick(right, |r| matches!(r, Ref::Api(_))) {
        found.insert(ChangeReason::Import);
    }
    let calls = |function: &FunctionRecord| -> Vec<u64> {
        function
            .refs
            .iter()
            .filter_map(|r| match r {
                Ref::Call(target) => Some(*target),
                _ => None,
            })
            .collect()
    };
    let (out_a, out_b) = (calls(left), calls(right));
    if out_a.len() != out_b.len()
        || out_a
            .iter()
            .zip(&out_b)
            .any(|(x, y)| forward.get(x) != Some(y))
    {
        found.insert(ChangeReason::Callee);
    }
    found.into_iter().collect()
}

fn only_in<T: Ord + Clone>(list: &[T], other: &[T]) -> Vec<T> {
    let other: BTreeSet<&T> = other.iter().collect();
    list.iter()
        .filter(|item| !other.contains(item))
        .take(MAX_LISTED)
        .cloned()
        .collect()
}

fn evidence(
    state: &Matcher<'_>,
    (x, y): (usize, usize),
    (left, right): (&FunctionRecord, &FunctionRecord),
    forward: &BTreeMap<u64, u64>,
    weighed: bool,
) -> Evidence {
    let empty = Vec::new();
    let refs = |graph: &Graph, at: usize, functions: &[FunctionRecord]| -> Vec<u64> {
        graph
            .callees
            .get(at)
            .unwrap_or(&empty)
            .iter()
            .filter_map(|to| functions.get(*to).map(|f| f.address))
            .collect()
    };
    let calls_a = refs(&state.graph_a, x, state.a);
    let calls_b = refs(&state.graph_b, y, state.b);
    let wanted: BTreeSet<u64> = calls_a
        .iter()
        .filter_map(|at| forward.get(at).copied())
        .collect();
    let got: BTreeSet<u64> = calls_b.iter().copied().collect();
    let record = |functions: &[FunctionRecord], at: u64| {
        functions
            .iter()
            .find(|f| f.address == at)
            .map(|f| FunctionRef {
                address: f.address,
                name: f.display.clone().or_else(|| f.name.clone()),
                instructions: f.instructions,
                ..FunctionRef::default()
            })
    };
    let mut out = Evidence {
        same_instructions: left.shape == right.shape,
        same_cfg: left.cfg == right.cfg,
        blocks: [left.blocks, right.blocks],
        edges: [left.edges, right.edges],
        signals: if weighed {
            state.signals(x, y)
        } else {
            Vec::new()
        },
        constants_only_a: only_in(&left.constants, &right.constants),
        constants_only_b: only_in(&right.constants, &left.constants),
        callees_only_a: calls_a
            .iter()
            .filter(|at| !forward.get(at).is_some_and(|peer| got.contains(peer)))
            .filter_map(|at| record(state.a, *at))
            .collect(),
        callees_only_b: calls_b
            .iter()
            .filter(|at| !wanted.contains(at))
            .filter_map(|at| record(state.b, *at))
            .collect(),
        ..Evidence::default()
    };
    if let (Some(ours), Some(theirs)) = (state.features_a.get(x), state.features_b.get(y)) {
        out.strings_only_a = only_in(&ours.strings, &theirs.strings);
        out.strings_only_b = only_in(&theirs.strings, &ours.strings);
        out.imports_only_a = only_in(&ours.apis, &theirs.apis);
        out.imports_only_b = only_in(&theirs.apis, &ours.apis);
    }
    out
}

pub(super) fn match_functions(a: &[FunctionRecord], b: &[FunctionRecord]) -> Outcome {
    let mut state = Matcher {
        a,
        b,
        features_a: a.iter().map(Features::new).collect(),
        features_b: b.iter().map(Features::new).collect(),
        graph_a: Graph::new(a),
        graph_b: Graph::new(b),
        a_to_b: vec![None; a.len()],
        b_to_a: vec![None; b.len()],
        found: BTreeMap::new(),
    };
    state.unique_hash(Method::Exact, 1, 1.0, |f| f.content);
    state.unique_hash(Method::Shape, SMALL_FUNCTION, 0.95, |f| f.shape);
    state.names();
    for _ in 0..MAX_ROUNDS {
        let mut moved = 0;
        loop {
            let step = state.propagate();
            moved += step;
            if step == 0 {
                break;
            }
        }
        moved += state.fuzzy();
        if moved == 0 {
            break;
        }
    }
    state.duplicates();
    // A last look around what the duplicates settled.
    while state.propagate() > 0 {}

    let forward: BTreeMap<u64, u64> = state
        .found
        .iter()
        .filter_map(|(x, (y, ..))| Some((a.get(*x)?.address, b.get(*y)?.address)))
        .collect();
    let mut matches = Vec::with_capacity(state.found.len());
    for (x, (y, method, confidence)) in &state.found {
        let (Some(left), Some(right)) = (a.get(*x), b.get(*y)) else {
            continue;
        };
        let why = reasons(left, right, &forward);
        let similarity = if why.is_empty() {
            1.0
        } else {
            // Whatever the score says, these are not the same function.
            state.score(*x, *y).min(0.999)
        };
        // An exact unchanged pair is proved by its hash; there is nothing further to weigh.
        let weighed = !why.is_empty() || *method != Method::Exact;
        matches.push(FunctionMatch {
            evidence: evidence(&state, (*x, *y), (left, right), &forward, weighed),
            a_addr: left.address,
            b_addr: right.address,
            a_name: left.display.clone().or_else(|| left.name.clone()),
            b_name: right.display.clone().or_else(|| right.name.clone()),
            method: *method,
            confidence: *confidence,
            similarity,
            changed: !why.is_empty(),
            reasons: why,
            a_instructions: left.instructions,
            b_instructions: right.instructions,
        });
    }
    Outcome {
        unmatched_a: state
            .free_a()
            .filter_map(|at| a.get(at))
            .map(function_ref)
            .collect(),
        unmatched_b: state
            .free_b()
            .filter_map(|at| b.get(at))
            .map(function_ref)
            .collect(),
        matches,
    }
}
