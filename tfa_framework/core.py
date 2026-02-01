"""
Toxic Flow Analysis (TFA) Framework
====================================
A Secure-by-Design framework for detecting and mitigating toxic flows
in LLM-based autonomous agent systems.

This implementation provides:
- Agent workflow graph modeling with trust/capability lattices
- Static toxic flow analysis using IFDS-inspired reachability
- Dynamic provenance tracking with cryptographic metadata
- Sanitizer specification and verification

Author: AlSobeh, Shatnawi, Khamaiseh
Target: i-ETC 2026 Conference
"""

from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, List, Set, Tuple, Optional, Callable, Any
from collections import defaultdict
import hashlib
import json
import time


class TrustLevel(IntEnum):
    """
    Trust lattice for information flow control.
    U (Untrusted) < P (Partially trusted/sanitized) < T (Trusted)
    """
    UNTRUSTED = 0
    PARTIAL = 1
    TRUSTED = 2
    
    @classmethod
    def join(cls, *levels: 'TrustLevel') -> 'TrustLevel':
        """Compute join (least upper bound) - returns minimum trust level."""
        if not levels:
            return cls.TRUSTED
        return cls(min(level.value for level in levels))
    
    @classmethod
    def meet(cls, *levels: 'TrustLevel') -> 'TrustLevel':
        """Compute meet (greatest lower bound) - returns maximum trust level."""
        if not levels:
            return cls.UNTRUSTED
        return cls(max(level.value for level in levels))


class CapabilityLevel(IntEnum):
    """
    Capability lattice for tool classification.
    READ < WRITE < SENSITIVE (exfiltration-capable)
    """
    READ = 0
    WRITE = 1
    SENSITIVE = 2
    
    def requires_trust(self) -> TrustLevel:
        """Return minimum trust level required for this capability."""
        if self == CapabilityLevel.SENSITIVE:
            return TrustLevel.TRUSTED
        elif self == CapabilityLevel.WRITE:
            return TrustLevel.PARTIAL
        return TrustLevel.UNTRUSTED


class NodeType(IntEnum):
    """Types of nodes in the agent workflow graph."""
    SOURCE = auto()
    LLM = auto()
    TOOL = auto()
    SANITIZER = auto()


@dataclass
class SanitizerSpec:
    """
    Formal specification for a sanitizer node.
    
    Attributes:
        name: Identifier for the sanitizer
        output_domain: Finite set of allowed outputs
        safe_outputs: Subset of output_domain considered safe
        trust_elevation: Function mapping input trust to output trust
        validator: Optional validation function
    """
    name: str
    output_domain: Set[str]
    safe_outputs: Set[str]
    trust_elevation: Callable[[TrustLevel], TrustLevel] = None
    validator: Optional[Callable[[str], bool]] = None
    
    def __post_init__(self):
        if self.trust_elevation is None:
            # Default: elevate to PARTIAL if output is safe
            self.trust_elevation = lambda t: TrustLevel.PARTIAL if t == TrustLevel.UNTRUSTED else t
    
    def verify(self, input_trust: TrustLevel, output_value: str) -> Tuple[bool, TrustLevel]:
        """
        Verify sanitizer output and compute resulting trust level.
        
        Returns:
            (is_valid, output_trust_level)
        """
        if output_value not in self.output_domain:
            return False, TrustLevel.UNTRUSTED
        
        if output_value not in self.safe_outputs:
            return True, TrustLevel.UNTRUSTED
        
        if self.validator and not self.validator(output_value):
            return False, TrustLevel.UNTRUSTED
        
        return True, self.trust_elevation(input_trust)


@dataclass
class Node:
    """Base class for workflow graph nodes."""
    id: str
    node_type: NodeType
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceNode(Node):
    """Data source node with trust annotation."""
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    description: str = ""
    
    def __post_init__(self):
        self.node_type = NodeType.SOURCE


@dataclass
class LLMNode(Node):
    """LLM reasoning component node."""
    model_name: str = "gpt-4"
    
    def __post_init__(self):
        self.node_type = NodeType.LLM


@dataclass 
class ToolNode(Node):
    """Tool/action node with capability annotation."""
    capability_level: CapabilityLevel = CapabilityLevel.READ
    tool_name: str = ""
    description: str = ""
    
    def __post_init__(self):
        self.node_type = NodeType.TOOL


@dataclass
class SanitizerNode(Node):
    """Sanitizer node with formal verification spec."""
    spec: SanitizerSpec = None
    
    def __post_init__(self):
        self.node_type = NodeType.SANITIZER


@dataclass
class Edge:
    """Directed edge in the workflow graph."""
    source_id: str
    target_id: str
    edge_type: str = "data_flow"  # data_flow, control_flow, parameter
    weight: float = 1.0


@dataclass
class ToxicFlow:
    """Represents a detected toxic flow vulnerability."""
    source_id: str
    sink_id: str
    path: List[str]
    propagated_trust: TrustLevel
    severity: str = "HIGH"
    description: str = ""
    
    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "sink": self.sink_id,
            "path": self.path,
            "trust_level": self.propagated_trust.name,
            "severity": self.severity,
            "description": self.description
        }


class AgentWorkflowGraph:
    """
    Represents an agent's workflow as a directed graph with trust
    and capability annotations.
    
    Supports:
    - Cyclic graphs (agent loops, reflexion patterns)
    - Multi-agent coordination via inter-agent edges
    - Trust propagation with fixed-point computation
    """
    
    def __init__(self, name: str = "agent_workflow"):
        self.name = name
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, List[str]] = defaultdict(list)
    
    def add_node(self, node: Node) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node
    
    def add_source(self, id: str, trust: TrustLevel, description: str = "") -> SourceNode:
        """Add a data source node."""
        node = SourceNode(id=id, node_type=NodeType.SOURCE, 
                         trust_level=trust, description=description)
        self.add_node(node)
        return node
    
    def add_llm(self, id: str, model_name: str = "gpt-4") -> LLMNode:
        """Add an LLM reasoning node."""
        node = LLMNode(id=id, node_type=NodeType.LLM, model_name=model_name)
        self.add_node(node)
        return node
    
    def add_tool(self, id: str, capability: CapabilityLevel, 
                 tool_name: str = "", description: str = "") -> ToolNode:
        """Add a tool/action node."""
        node = ToolNode(id=id, node_type=NodeType.TOOL,
                       capability_level=capability, tool_name=tool_name,
                       description=description)
        self.add_node(node)
        return node
    
    def add_sanitizer(self, id: str, spec: SanitizerSpec) -> SanitizerNode:
        """Add a sanitizer node with verification spec."""
        node = SanitizerNode(id=id, node_type=NodeType.SANITIZER, spec=spec)
        self.add_node(node)
        return node
    
    def add_edge(self, source_id: str, target_id: str, 
                 edge_type: str = "data_flow") -> None:
        """Add a directed edge between nodes."""
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError(f"Both nodes must exist: {source_id}, {target_id}")
        
        edge = Edge(source_id=source_id, target_id=target_id, edge_type=edge_type)
        self.edges.append(edge)
        self._adjacency[source_id].append(target_id)
        self._reverse_adjacency[target_id].append(source_id)
    
    def get_untrusted_sources(self) -> List[SourceNode]:
        """Return all nodes marked as untrusted sources."""
        return [n for n in self.nodes.values() 
                if isinstance(n, SourceNode) and n.trust_level == TrustLevel.UNTRUSTED]
    
    def get_sensitive_sinks(self) -> List[ToolNode]:
        """Return all nodes marked as sensitive tools."""
        return [n for n in self.nodes.values()
                if isinstance(n, ToolNode) and n.capability_level == CapabilityLevel.SENSITIVE]
    
    def get_successors(self, node_id: str) -> List[str]:
        """Return IDs of all successor nodes."""
        return self._adjacency.get(node_id, [])
    
    def get_predecessors(self, node_id: str) -> List[str]:
        """Return IDs of all predecessor nodes."""
        return self._reverse_adjacency.get(node_id, [])
    
    def has_cycles(self) -> bool:
        """Check if the graph contains cycles using DFS."""
        visited = set()
        rec_stack = set()
        
        def dfs(node_id):
            visited.add(node_id)
            rec_stack.add(node_id)
            
            for neighbor in self.get_successors(node_id):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node_id)
            return False
        
        for node_id in self.nodes:
            if node_id not in visited:
                if dfs(node_id):
                    return True
        return False
    
    def to_dict(self) -> dict:
        """Serialize graph to dictionary."""
        return {
            "name": self.name,
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.name,
                    "trust": n.trust_level.name if hasattr(n, 'trust_level') else None,
                    "capability": n.capability_level.name if hasattr(n, 'capability_level') else None
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id, "type": e.edge_type}
                for e in self.edges
            ]
        }
    
    def __repr__(self) -> str:
        return f"AgentWorkflowGraph(name={self.name}, nodes={len(self.nodes)}, edges={len(self.edges)})"


class ToxicFlowAnalyzer:
    """
    Static analyzer for detecting toxic flows in agent workflow graphs.
    
    Implements IFDS-inspired reachability analysis with trust propagation
    through information-flow lattices.
    """
    
    def __init__(self, max_iterations: int = 100):
        self.max_iterations = max_iterations
        self.analysis_stats = {}
    
    def analyze(self, graph: AgentWorkflowGraph) -> List[ToxicFlow]:
        """
        Perform toxic flow analysis on the workflow graph.
        
        Algorithm:
        1. Identify all untrusted sources and sensitive sinks
        2. For each source, compute reachable sinks with trust propagation
        3. Report paths where untrusted data reaches sensitive sinks
        
        Returns:
            List of detected ToxicFlow vulnerabilities
        """
        start_time = time.time()
        toxic_flows = []
        
        untrusted_sources = graph.get_untrusted_sources()
        sensitive_sinks = graph.get_sensitive_sinks()
        
        if not untrusted_sources or not sensitive_sinks:
            self.analysis_stats = {
                "time_ms": (time.time() - start_time) * 1000,
                "sources_checked": len(untrusted_sources),
                "sinks_checked": len(sensitive_sinks),
                "flows_detected": 0
            }
            return toxic_flows
        
        sink_ids = {s.id for s in sensitive_sinks}
        
        for source in untrusted_sources:
            flows = self._find_toxic_flows(graph, source, sink_ids)
            toxic_flows.extend(flows)
        
        self.analysis_stats = {
            "time_ms": (time.time() - start_time) * 1000,
            "sources_checked": len(untrusted_sources),
            "sinks_checked": len(sensitive_sinks),
            "flows_detected": len(toxic_flows),
            "has_cycles": graph.has_cycles()
        }
        
        return toxic_flows
    
    def _find_toxic_flows(self, graph: AgentWorkflowGraph, 
                         source: SourceNode, 
                         sink_ids: Set[str]) -> List[ToxicFlow]:
        """
        Find all toxic flows from a source to any sensitive sink.
        Uses BFS with trust propagation and cycle handling.
        """
        flows = []
        
        # State: (node_id, trust_level, path)
        queue = [(source.id, source.trust_level, [source.id])]
        
        # Track visited states: node_id -> minimum trust level seen
        visited: Dict[str, TrustLevel] = {}
        
        iteration = 0
        while queue and iteration < self.max_iterations * len(graph.nodes):
            iteration += 1
            current_id, current_trust, path = queue.pop(0)
            
            # Skip if we've visited this node with equal or lower trust
            if current_id in visited:
                if visited[current_id].value <= current_trust.value:
                    continue
            
            visited[current_id] = current_trust
            
            # Check if we reached a sensitive sink with untrusted data
            if current_id in sink_ids and current_trust == TrustLevel.UNTRUSTED:
                sink_node = graph.nodes[current_id]
                flow = ToxicFlow(
                    source_id=source.id,
                    sink_id=current_id,
                    path=path.copy(),
                    propagated_trust=current_trust,
                    severity="HIGH" if sink_node.capability_level == CapabilityLevel.SENSITIVE else "MEDIUM",
                    description=f"Untrusted data from '{source.description or source.id}' "
                               f"reaches sensitive sink '{sink_node.tool_name or current_id}'"
                )
                flows.append(flow)
                continue  # Don't propagate past sinks
            
            # Propagate to successors
            for successor_id in graph.get_successors(current_id):
                if successor_id in path and len(path) > 10:
                    # Prevent infinite loops but allow bounded cycles
                    continue
                
                successor = graph.nodes[successor_id]
                new_trust = self._propagate_trust(current_trust, successor)
                new_path = path + [successor_id]
                
                queue.append((successor_id, new_trust, new_path))
        
        return flows
    
    def _propagate_trust(self, input_trust: TrustLevel, node: Node) -> TrustLevel:
        """
        Compute output trust level based on node type.
        
        Rules:
        - Sanitizers may elevate trust if verified
        - LLMs propagate minimum input trust (conservative)
        - Tools propagate input trust unchanged
        """
        if isinstance(node, SanitizerNode) and node.spec:
            # Sanitizer can elevate trust if properly specified
            # For static analysis, assume best case (verified)
            return node.spec.trust_elevation(input_trust)
        
        elif isinstance(node, LLMNode):
            # LLM cannot launder trust - propagate as-is
            return input_trust
        
        elif isinstance(node, SourceNode):
            # Join with source's trust level
            return TrustLevel.join(input_trust, node.trust_level)
        
        # Default: propagate unchanged
        return input_trust
    
    def get_stats(self) -> dict:
        """Return analysis statistics from last run."""
        return self.analysis_stats


@dataclass
class Provenance:
    """Cryptographic provenance metadata for runtime tracking."""
    origin: str
    trust_level: TrustLevel
    content_hash: str
    timestamp: float
    chain: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "origin": self.origin,
            "trust": self.trust_level.name,
            "hash": self.content_hash,
            "timestamp": self.timestamp,
            "chain": self.chain
        }


class ProvenanceTracker:
    """
    Runtime provenance tracking with cryptographic integrity.
    
    Maintains metadata for all content processed by the agent,
    enabling dynamic trust verification at tool invocation.
    """
    
    def __init__(self):
        self.metadata: Dict[str, Provenance] = {}
        self.origin_map: Dict[str, List[str]] = defaultdict(list)
    
    def tag(self, content: str, origin: str, trust: TrustLevel) -> str:
        """
        Tag content with provenance metadata.
        
        Returns:
            Content hash for future reference
        """
        content_hash = self._compute_hash(content)
        
        provenance = Provenance(
            origin=origin,
            trust_level=trust,
            content_hash=content_hash,
            timestamp=time.time(),
            chain=[origin]
        )
        
        self.metadata[content_hash] = provenance
        self.origin_map[origin].append(content_hash)
        
        return content_hash
    
    def derive(self, new_content: str, source_hashes: List[str], 
               processor: str) -> str:
        """
        Create derived content with propagated provenance.
        
        Trust level is the join (minimum) of all source trust levels.
        """
        new_hash = self._compute_hash(new_content)
        
        # Compute derived trust level
        source_trusts = []
        combined_chain = []
        
        for src_hash in source_hashes:
            if src_hash in self.metadata:
                src_prov = self.metadata[src_hash]
                source_trusts.append(src_prov.trust_level)
                combined_chain.extend(src_prov.chain)
        
        derived_trust = TrustLevel.join(*source_trusts) if source_trusts else TrustLevel.UNTRUSTED
        
        provenance = Provenance(
            origin=f"derived:{processor}",
            trust_level=derived_trust,
            content_hash=new_hash,
            timestamp=time.time(),
            chain=list(set(combined_chain)) + [processor]
        )
        
        self.metadata[new_hash] = provenance
        return new_hash
    
    def verify(self, content: str, required_trust: TrustLevel) -> Tuple[bool, Optional[Provenance]]:
        """
        Verify content meets trust requirements.
        
        Returns:
            (meets_requirement, provenance_if_found)
        """
        content_hash = self._compute_hash(content)
        
        if content_hash not in self.metadata:
            # Unknown content treated as untrusted
            return required_trust == TrustLevel.UNTRUSTED, None
        
        provenance = self.metadata[content_hash]
        meets_req = provenance.trust_level.value >= required_trust.value
        
        return meets_req, provenance
    
    def get_provenance(self, content: str) -> Optional[Provenance]:
        """Retrieve provenance for content if tracked."""
        content_hash = self._compute_hash(content)
        return self.metadata.get(content_hash)
    
    def _compute_hash(self, content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
    
    def clear(self) -> None:
        """Clear all tracked provenance."""
        self.metadata.clear()
        self.origin_map.clear()


class DynamicEnforcer:
    """
    Runtime enforcement layer for toxic flow prevention.
    
    Integrates with ProvenanceTracker to enforce trust policies
    at tool invocation time.
    """
    
    def __init__(self, tracker: ProvenanceTracker):
        self.tracker = tracker
        self.blocked_actions = []
        self.allowed_actions = []
    
    def check_tool_invocation(self, tool: ToolNode, 
                              parameters: Dict[str, str]) -> Tuple[bool, str]:
        """
        Check if tool invocation should be allowed.
        
        Returns:
            (allowed, reason)
        """
        required_trust = tool.capability_level.requires_trust()
        
        for param_name, param_value in parameters.items():
            meets_req, provenance = self.tracker.verify(param_value, required_trust)
            
            if not meets_req:
                reason = (f"Parameter '{param_name}' has trust level "
                         f"{provenance.trust_level.name if provenance else 'UNKNOWN'}, "
                         f"but tool '{tool.tool_name}' requires {required_trust.name}")
                
                self.blocked_actions.append({
                    "tool": tool.id,
                    "param": param_name,
                    "reason": reason,
                    "timestamp": time.time()
                })
                
                return False, reason
        
        self.allowed_actions.append({
            "tool": tool.id,
            "timestamp": time.time()
        })
        
        return True, "All parameters meet trust requirements"
    
    def get_blocked_count(self) -> int:
        """Return number of blocked actions."""
        return len(self.blocked_actions)
    
    def get_audit_log(self) -> dict:
        """Return audit log of enforcement decisions."""
        return {
            "blocked": self.blocked_actions,
            "allowed": self.allowed_actions
        }


# Pre-defined sanitizer specifications
BOOLEAN_SANITIZER = SanitizerSpec(
    name="boolean_gate",
    output_domain={"true", "false"},
    safe_outputs={"true", "false"},
    trust_elevation=lambda t: TrustLevel.PARTIAL
)

APPROVAL_SANITIZER = SanitizerSpec(
    name="approval_gate", 
    output_domain={"approve", "deny", "escalate"},
    safe_outputs={"approve", "deny", "escalate"},
    trust_elevation=lambda t: TrustLevel.PARTIAL
)

HITL_SANITIZER = SanitizerSpec(
    name="human_in_the_loop",
    output_domain={"confirmed", "rejected"},
    safe_outputs={"confirmed"},
    trust_elevation=lambda t: TrustLevel.TRUSTED  # Human approval elevates to full trust
)


def create_github_mcp_scenario() -> AgentWorkflowGraph:
    """
    Create the GitHub MCP exploit scenario workflow graph.
    Demonstrates toxic flow from malicious issue to data exfiltration.
    """
    graph = AgentWorkflowGraph(name="github_mcp_exploit")
    
    # Sources
    graph.add_source("user_prompt", TrustLevel.TRUSTED, 
                    "Legitimate user instruction")
    graph.add_source("github_issue", TrustLevel.UNTRUSTED,
                    "External GitHub issue content")
    
    # LLM reasoning
    graph.add_llm("llm_planner", "gpt-4")
    
    # Tools
    graph.add_tool("git_read_file", CapabilityLevel.WRITE,
                  "git_read_file", "Read files from repository")
    graph.add_tool("send_network", CapabilityLevel.SENSITIVE,
                  "send_network_request", "Send HTTP requests externally")
    graph.add_tool("summarize", CapabilityLevel.READ,
                  "text_summarize", "Summarize text content")
    
    # Edges representing workflow
    graph.add_edge("user_prompt", "llm_planner")
    graph.add_edge("github_issue", "llm_planner")
    graph.add_edge("llm_planner", "git_read_file")
    graph.add_edge("llm_planner", "summarize")
    graph.add_edge("git_read_file", "llm_planner")  # Results fed back
    graph.add_edge("llm_planner", "send_network")  # Toxic flow target
    
    return graph


def create_mitigated_github_scenario() -> AgentWorkflowGraph:
    """
    Create mitigated version with sanitizer and trust controls.
    """
    graph = AgentWorkflowGraph(name="github_mcp_mitigated")
    
    # Sources
    graph.add_source("user_prompt", TrustLevel.TRUSTED,
                    "Legitimate user instruction")
    graph.add_source("github_issue", TrustLevel.UNTRUSTED,
                    "External GitHub issue content")
    
    # Sanitizer for external content
    graph.add_sanitizer("content_sanitizer", APPROVAL_SANITIZER)
    
    # HITL gate for sensitive actions
    graph.add_sanitizer("hitl_gate", HITL_SANITIZER)
    
    # LLM reasoning
    graph.add_llm("llm_planner", "gpt-4")
    
    # Tools
    graph.add_tool("git_read_file", CapabilityLevel.WRITE,
                  "git_read_file", "Read files from repository")
    graph.add_tool("send_network", CapabilityLevel.SENSITIVE,
                  "send_network_request", "Send HTTP requests externally")
    
    # Mitigated workflow
    graph.add_edge("user_prompt", "llm_planner")
    graph.add_edge("github_issue", "content_sanitizer")  # Sanitize external content
    graph.add_edge("content_sanitizer", "llm_planner")
    graph.add_edge("llm_planner", "git_read_file")
    graph.add_edge("git_read_file", "llm_planner")
    graph.add_edge("llm_planner", "hitl_gate")  # HITL before sensitive action
    graph.add_edge("hitl_gate", "send_network")
    
    return graph


if __name__ == "__main__":
    # Demonstrate TFA on GitHub MCP scenario
    print("=" * 60)
    print("Toxic Flow Analysis Framework Demonstration")
    print("=" * 60)
    
    # Analyze vulnerable scenario
    print("\n1. Analyzing vulnerable GitHub MCP scenario...")
    vulnerable_graph = create_github_mcp_scenario()
    analyzer = ToxicFlowAnalyzer()
    
    flows = analyzer.analyze(vulnerable_graph)
    stats = analyzer.get_stats()
    
    print(f"   Graph: {vulnerable_graph}")
    print(f"   Analysis time: {stats['time_ms']:.2f}ms")
    print(f"   Toxic flows detected: {len(flows)}")
    
    for flow in flows:
        print(f"\n   VULNERABILITY DETECTED:")
        print(f"   - Source: {flow.source_id}")
        print(f"   - Sink: {flow.sink_id}")
        print(f"   - Path: {' -> '.join(flow.path)}")
        print(f"   - Severity: {flow.severity}")
    
    # Analyze mitigated scenario
    print("\n" + "=" * 60)
    print("2. Analyzing mitigated GitHub MCP scenario...")
    mitigated_graph = create_mitigated_github_scenario()
    
    flows_mitigated = analyzer.analyze(mitigated_graph)
    stats_mitigated = analyzer.get_stats()
    
    print(f"   Graph: {mitigated_graph}")
    print(f"   Analysis time: {stats_mitigated['time_ms']:.2f}ms")
    print(f"   Toxic flows detected: {len(flows_mitigated)}")
    
    if not flows_mitigated:
        print("\n   SUCCESS: No toxic flows detected in mitigated design!")
    
    print("\n" + "=" * 60)
    print("Framework demonstration complete.")
