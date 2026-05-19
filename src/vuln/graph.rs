//! EvidenceGraph — the central abstraction.
//!
//! Every existing axe analysis (functions, CFG, SSA, dataflow,
//! value-graph, VSA, xrefs, attack, behavior dossiers, API flows,
//! imports) becomes a node-/edge-producing ingestor into one
//! `EvidenceGraph` (built per `run_vuln_discovery` invocation; never
//! persisted across runs in v1.0 — see Codex preempt C).
//!
//! v1.0 ships **15 NodeKinds + 12 EdgeKinds**. v1.1 adds:
//! - `NodeKind::DynamicObservation` (per-chain dynamic evidence)
//! - `EdgeKind::ConfirmedByTrace`, `EdgeKind::ConfirmedByCrash`,
//!   `EdgeKind::AliasMustPointTo` (added when better alias analysis
//!   ships).
//!
//! Memory discipline (Codex preempt 6 from the v1 draft): nodes
//! carry payload variants with handles (VA, name strings, register
//! IDs) into the existing analysis records, NOT copies of the
//! records themselves. Bound: ~64 bytes/node × node count + edge
//! count × ~16 bytes.

#![allow(dead_code)]

use petgraph::graph::{EdgeIndex, Graph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

pub type NodeId = NodeIndex<u32>;
pub type EdgeId = EdgeIndex<u32>;

/// Discriminator for a graph node. Same enum is matched by every
/// downstream pass (chain query, guard analysis, scoring) so adding a
/// variant means updating each consumer exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Function,
    BasicBlock,
    CallSite,
    Source,
    Sink,
    Sanitizer,
    BoundsCheck,
    Allocation,
    Copy,
    ParseStep,
    TypeCast,
    IntegerOp,
    PointerDerivation,
    BranchCondition,
    GlobalState,
}

/// Discriminator for a graph edge. v1.0 = 12 variants; v1.1 adds
/// `ConfirmedByTrace` + `ConfirmedByCrash` once per-chain dynamic
/// attribution lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Calls,
    ControlFlow,
    DataFlow,
    TaintFlow,
    Dominates,
    PostDominates,
    GuardedBy,
    Reaches,
    DerivedFrom,
    WritesTo,
    ReadsFrom,
    AliasMayPointTo,
}

/// Payload carried by a graph node. Variants are intentionally
/// minimal — they hold handles (VA, name, register ID) into the
/// existing analysis records, not record copies. The chain-query
/// engine resolves payloads back to record details by VA lookup.
///
/// Wire form uses `node_kind` as the discriminator tag (not `kind`)
/// because three variants — `Source`, `Sanitizer`, `ParseStep` —
/// already have a `kind: String` field whose value is the catalog
/// entry name. Using a distinct tag name avoids the serde collision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "node_kind", rename_all = "snake_case")]
pub enum NodePayload {
    Function {
        va: u64,
        name: Option<String>,
    },
    BasicBlock {
        function_va: u64,
        start_va: u64,
        end_va: u64,
    },
    CallSite {
        va: u64,
        target_va: Option<u64>,
        api: Option<String>,
    },
    /// Reference to a `SourceCatalog` entry (resolved at chain time).
    Source {
        kind: String,
        locator: String,
    },
    /// Reference to a `SinkCatalog` entry + the call-site VA.
    Sink {
        api: String,
        site_va: u64,
    },
    Sanitizer {
        kind: String,
        va: u64,
    },
    BoundsCheck {
        var: String,
        va: u64,
    },
    Allocation {
        size_expr: String,
        va: u64,
    },
    Copy {
        dst_var: String,
        src_var: String,
        va: u64,
    },
    ParseStep {
        kind: String,
        va: u64,
    },
    TypeCast {
        from_bits: u32,
        to_bits: u32,
        signed: bool,
        va: u64,
    },
    IntegerOp {
        op: String,
        va: u64,
    },
    PointerDerivation {
        base: String,
        offset: i64,
        va: u64,
    },
    BranchCondition {
        condition: String,
        va: u64,
    },
    GlobalState {
        key: String,
    },
}

impl NodePayload {
    /// Return the discriminator that classifies this payload.
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Function { .. } => NodeKind::Function,
            Self::BasicBlock { .. } => NodeKind::BasicBlock,
            Self::CallSite { .. } => NodeKind::CallSite,
            Self::Source { .. } => NodeKind::Source,
            Self::Sink { .. } => NodeKind::Sink,
            Self::Sanitizer { .. } => NodeKind::Sanitizer,
            Self::BoundsCheck { .. } => NodeKind::BoundsCheck,
            Self::Allocation { .. } => NodeKind::Allocation,
            Self::Copy { .. } => NodeKind::Copy,
            Self::ParseStep { .. } => NodeKind::ParseStep,
            Self::TypeCast { .. } => NodeKind::TypeCast,
            Self::IntegerOp { .. } => NodeKind::IntegerOp,
            Self::PointerDerivation { .. } => NodeKind::PointerDerivation,
            Self::BranchCondition { .. } => NodeKind::BranchCondition,
            Self::GlobalState { .. } => NodeKind::GlobalState,
        }
    }

    /// Return the VA the payload anchors at, when meaningful. Used by
    /// scoring (`reachability_score`) and by chain serialization
    /// (`path[].va`).
    pub fn anchor_va(&self) -> Option<u64> {
        match self {
            Self::Function { va, .. }
            | Self::CallSite { va, .. }
            | Self::Sanitizer { va, .. }
            | Self::BoundsCheck { va, .. }
            | Self::Allocation { va, .. }
            | Self::Copy { va, .. }
            | Self::ParseStep { va, .. }
            | Self::TypeCast { va, .. }
            | Self::IntegerOp { va, .. }
            | Self::PointerDerivation { va, .. }
            | Self::BranchCondition { va, .. } => Some(*va),
            Self::Sink { site_va, .. } => Some(*site_va),
            Self::BasicBlock { start_va, .. } => Some(*start_va),
            Self::Source { .. } | Self::GlobalState { .. } => None,
        }
    }
}

/// The canonical analysis graph. Wraps `petgraph::Graph` plus a few
/// hot lookup indices (function-by-VA, block-by-VA-pair). Lifetime =
/// single `run_vuln_discovery` invocation.
pub struct EvidenceGraph {
    inner: Graph<NodePayload, EdgeKind, petgraph::Directed, u32>,
    function_index: FxHashMap<u64, NodeId>,
    block_index: FxHashMap<(u64, u64), NodeId>,
    sink_index: FxHashMap<u64, NodeId>,
}

impl Default for EvidenceGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceGraph {
    pub fn new() -> Self {
        Self {
            inner: Graph::with_capacity(1024, 4096),
            function_index: FxHashMap::default(),
            block_index: FxHashMap::default(),
            sink_index: FxHashMap::default(),
        }
    }

    /// Add a node. Updates indices for `Function` / `BasicBlock` /
    /// `Sink` payloads to keep VA-based lookups O(1).
    pub fn add_node(&mut self, payload: NodePayload) -> NodeId {
        let function_key = matches!(&payload, NodePayload::Function { .. })
            .then(|| payload.anchor_va())
            .flatten();
        let block_key = if let NodePayload::BasicBlock {
            function_va,
            start_va,
            ..
        } = &payload
        {
            Some((*function_va, *start_va))
        } else {
            None
        };
        let sink_key = matches!(&payload, NodePayload::Sink { .. })
            .then(|| payload.anchor_va())
            .flatten();
        let id = self.inner.add_node(payload);
        if let Some(va) = function_key {
            self.function_index.insert(va, id);
        }
        if let Some(key) = block_key {
            self.block_index.insert(key, id);
        }
        if let Some(va) = sink_key {
            self.sink_index.insert(va, id);
        }
        id
    }

    pub fn add_edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) -> EdgeId {
        self.inner.add_edge(from, to, kind)
    }

    pub fn node(&self, id: NodeId) -> Option<&NodePayload> {
        self.inner.node_weight(id)
    }

    pub fn edge_kind(&self, id: EdgeId) -> Option<EdgeKind> {
        self.inner.edge_weight(id).copied()
    }

    pub fn function_by_va(&self, va: u64) -> Option<NodeId> {
        self.function_index.get(&va).copied()
    }

    pub fn block_by_va(&self, function_va: u64, start_va: u64) -> Option<NodeId> {
        self.block_index.get(&(function_va, start_va)).copied()
    }

    pub fn sink_by_va(&self, va: u64) -> Option<NodeId> {
        self.sink_index.get(&va).copied()
    }

    pub fn node_count(&self) -> usize {
        self.inner.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    /// Iterator over (NodeId, &NodePayload) restricted to one kind.
    pub fn nodes_of_kind<'a>(
        &'a self,
        kind: NodeKind,
    ) -> impl Iterator<Item = (NodeId, &'a NodePayload)> + 'a {
        self.inner.node_indices().filter_map(move |id| {
            let payload = self.inner.node_weight(id)?;
            if payload.kind() == kind {
                Some((id, payload))
            } else {
                None
            }
        })
    }

    /// Iterator over outgoing edges of a node, restricted to one kind.
    pub fn outgoing_of_kind<'a>(
        &'a self,
        node: NodeId,
        kind: EdgeKind,
    ) -> impl Iterator<Item = (NodeId, EdgeId)> + 'a {
        self.inner
            .edges_directed(node, Direction::Outgoing)
            .filter_map(move |e| {
                if *e.weight() == kind {
                    Some((e.target(), e.id()))
                } else {
                    None
                }
            })
    }

    /// Iterator over incoming edges of a node, restricted to one kind.
    pub fn incoming_of_kind<'a>(
        &'a self,
        node: NodeId,
        kind: EdgeKind,
    ) -> impl Iterator<Item = (NodeId, EdgeId)> + 'a {
        self.inner
            .edges_directed(node, Direction::Incoming)
            .filter_map(move |e| {
                if *e.weight() == kind {
                    Some((e.source(), e.id()))
                } else {
                    None
                }
            })
    }

    /// Read-only access to the underlying petgraph for algorithms
    /// (dominators, dijkstra, etc.) that need it.
    pub fn raw(&self) -> &Graph<NodePayload, EdgeKind, petgraph::Directed, u32> {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(va: u64, name: &str) -> NodePayload {
        NodePayload::Function {
            va,
            name: Some(name.into()),
        }
    }
    fn block(fva: u64, sva: u64, eva: u64) -> NodePayload {
        NodePayload::BasicBlock {
            function_va: fva,
            start_va: sva,
            end_va: eva,
        }
    }
    fn sink(api: &str, va: u64) -> NodePayload {
        NodePayload::Sink {
            api: api.into(),
            site_va: va,
        }
    }

    #[test]
    fn empty_graph_has_zero_nodes_and_edges() {
        let g = EvidenceGraph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn add_node_increments_count_and_returns_id() {
        let mut g = EvidenceGraph::new();
        let a = g.add_node(func(0x1000, "main"));
        let b = g.add_node(func(0x2000, "helper"));
        assert_ne!(a, b);
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn function_by_va_returns_added_node() {
        let mut g = EvidenceGraph::new();
        let id = g.add_node(func(0x140012a40, "parse_packet"));
        assert_eq!(g.function_by_va(0x140012a40), Some(id));
        assert!(g.function_by_va(0xdeadbeef).is_none());
    }

    #[test]
    fn block_by_va_uses_function_plus_start_pair() {
        let mut g = EvidenceGraph::new();
        let id = g.add_node(block(0x1000, 0x1010, 0x1020));
        assert_eq!(g.block_by_va(0x1000, 0x1010), Some(id));
        // Different function-va same start-va → miss.
        assert!(g.block_by_va(0x2000, 0x1010).is_none());
    }

    #[test]
    fn sink_by_va_indexes_site_va() {
        let mut g = EvidenceGraph::new();
        let id = g.add_node(sink("memcpy", 0x4022a4));
        assert_eq!(g.sink_by_va(0x4022a4), Some(id));
    }

    #[test]
    fn add_edge_with_typed_kind() {
        let mut g = EvidenceGraph::new();
        let a = g.add_node(func(0x1000, "a"));
        let b = g.add_node(func(0x2000, "b"));
        let e = g.add_edge(a, b, EdgeKind::Calls);
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.edge_kind(e), Some(EdgeKind::Calls));
    }

    #[test]
    fn nodes_of_kind_filters_correctly() {
        let mut g = EvidenceGraph::new();
        g.add_node(func(0x1000, "f1"));
        g.add_node(func(0x2000, "f2"));
        g.add_node(sink("memcpy", 0x3000));
        let functions: Vec<_> = g.nodes_of_kind(NodeKind::Function).collect();
        let sinks: Vec<_> = g.nodes_of_kind(NodeKind::Sink).collect();
        assert_eq!(functions.len(), 2);
        assert_eq!(sinks.len(), 1);
    }

    #[test]
    fn outgoing_of_kind_filters_by_edge_kind() {
        let mut g = EvidenceGraph::new();
        let a = g.add_node(func(0x1000, "a"));
        let b = g.add_node(func(0x2000, "b"));
        let c = g.add_node(func(0x3000, "c"));
        g.add_edge(a, b, EdgeKind::Calls);
        g.add_edge(a, c, EdgeKind::DataFlow);
        let calls: Vec<_> = g.outgoing_of_kind(a, EdgeKind::Calls).collect();
        let dataflow: Vec<_> = g.outgoing_of_kind(a, EdgeKind::DataFlow).collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(dataflow.len(), 1);
        assert_eq!(calls[0].0, b);
        assert_eq!(dataflow[0].0, c);
    }

    #[test]
    fn payload_kind_discriminator_matches_variant() {
        assert_eq!(func(0x1000, "x").kind(), NodeKind::Function);
        assert_eq!(sink("memcpy", 0x4000).kind(), NodeKind::Sink);
        assert_eq!(
            NodePayload::Allocation {
                size_expr: "len".into(),
                va: 0x5000
            }
            .kind(),
            NodeKind::Allocation
        );
    }

    #[test]
    fn payload_anchor_va_returns_some_for_va_carrying_variants() {
        assert_eq!(func(0x1234, "f").anchor_va(), Some(0x1234));
        assert_eq!(sink("memcpy", 0x4022).anchor_va(), Some(0x4022));
        assert_eq!(
            NodePayload::Source {
                kind: "recv".into(),
                locator: "p".into()
            }
            .anchor_va(),
            None
        );
    }

    #[test]
    fn node_payload_round_trips_through_json() {
        let p = NodePayload::TypeCast {
            from_bits: 32,
            to_bits: 64,
            signed: true,
            va: 0x12340,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains(r#""node_kind":"type_cast""#));
        let back: NodePayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }
}
