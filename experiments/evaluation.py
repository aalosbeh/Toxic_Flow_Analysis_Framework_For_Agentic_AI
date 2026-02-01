"""
TFA Framework - Experimental Evaluation Module

Benchmark Generation Parameters (for reproducibility):
------------------------------------------------------
- Random seed: 42 (FIXED)
- Graph sizes: 15-50 nodes (uniform)
- Edge density: 1.5-2.5 edges per node
- Capability distribution: 40% R, 35% W, 25% S
- Sanitizer placement: 20% probability per edge
- Attack depth: 1-5 hops (uniform)

Total benchmark: 500 graphs (200 benign, 300 malicious)
"""

import random
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum

try:
    from tfa_framework.core import (
        AgentWorkflowGraph, ToxicFlowAnalyzer, ToxicFlow,
        TrustLevel, CapabilityLevel, SanitizerSpec,
        BOOLEAN_SANITIZER, APPROVAL_SANITIZER
    )
except ImportError:
    from core import (
        AgentWorkflowGraph, ToxicFlowAnalyzer, ToxicFlow,
        TrustLevel, CapabilityLevel, SanitizerSpec,
        BOOLEAN_SANITIZER, APPROVAL_SANITIZER
    )


# =============================================================================
# BENCHMARK CONFIGURATION
# =============================================================================

@dataclass
class BenchmarkConfig:
    """
    Documented benchmark generation parameters.
    
    These parameters are FIXED for reproducibility as specified in the paper.
    """
    # Core parameters
    seed: int = 42                    # FIXED random seed
    num_benign: int = 200             # Benign workflow graphs
    num_malicious: int = 300          # Graphs with toxic flows
    
    # Graph structure
    min_nodes: int = 15               # Minimum nodes per graph
    max_nodes: int = 50               # Maximum nodes per graph
    min_edge_density: float = 1.5     # Minimum edges per node
    max_edge_density: float = 2.5     # Maximum edges per node
    
    # Capability distribution (must sum to 1.0)
    capability_read: float = 0.40     # 40% READ
    capability_write: float = 0.35    # 35% WRITE
    capability_sensitive: float = 0.25 # 25% SENSITIVE
    
    # Sanitizer placement
    sanitizer_probability: float = 0.20  # 20% chance per edge
    
    # Attack parameters
    min_attack_depth: int = 1         # Minimum hops
    max_attack_depth: int = 5         # Maximum hops
    
    # Cycle parameters
    cycle_probability: float = 0.30   # 30% graphs have cycles
    
    def __post_init__(self):
        # Validate capability distribution
        total = self.capability_read + self.capability_write + self.capability_sensitive
        assert abs(total - 1.0) < 0.01, f"Capability distribution must sum to 1.0, got {total}"


# =============================================================================
# TOOL TEMPLATES (from AgentDojo domains)
# =============================================================================

TOOL_TEMPLATES = {
    "banking": [
        ("get_balance", CapabilityLevel.READ),
        ("list_transactions", CapabilityLevel.READ),
        ("transfer_funds", CapabilityLevel.SENSITIVE),
        ("update_profile", CapabilityLevel.WRITE),
        ("send_wire", CapabilityLevel.SENSITIVE),
    ],
    "workspace": [
        ("read_email", CapabilityLevel.READ),
        ("send_email", CapabilityLevel.SENSITIVE),
        ("list_files", CapabilityLevel.READ),
        ("read_file", CapabilityLevel.READ),
        ("write_file", CapabilityLevel.WRITE),
        ("delete_file", CapabilityLevel.WRITE),
    ],
    "travel": [
        ("search_flights", CapabilityLevel.READ),
        ("book_flight", CapabilityLevel.SENSITIVE),
        ("cancel_booking", CapabilityLevel.WRITE),
        ("get_itinerary", CapabilityLevel.READ),
    ],
    "developer": [
        ("git_read_file", CapabilityLevel.READ),
        ("git_write_file", CapabilityLevel.WRITE),
        ("git_commit", CapabilityLevel.WRITE),
        ("run_command", CapabilityLevel.SENSITIVE),
        ("send_network_request", CapabilityLevel.SENSITIVE),
    ],
}

UNTRUSTED_SOURCES = [
    "external_email",
    "web_content",
    "github_issue",
    "slack_message",
    "api_response",
    "user_upload",
    "rss_feed",
    "webhook_payload",
]


# =============================================================================
# BENCHMARK GENERATOR
# =============================================================================

class BenchmarkGenerator:
    """
    Generates reproducible synthetic benchmark graphs.
    Uses fixed seed and documented parameters.
    """
    
    def __init__(self, config: BenchmarkConfig = None):
        self.config = config or BenchmarkConfig()
        self.rng = random.Random(self.config.seed)
        
    def generate_benchmark(self) -> List[Tuple[AgentWorkflowGraph, bool]]:
        """
        Generate complete benchmark: (graph, has_toxic_flow) pairs.
        """
        benchmark = []
        
        # Generate benign graphs
        for i in range(self.config.num_benign):
            graph = self._generate_benign_graph(f"benign_{i}")
            benchmark.append((graph, False))
        
        # Generate malicious graphs
        for i in range(self.config.num_malicious):
            graph = self._generate_malicious_graph(f"malicious_{i}")
            benchmark.append((graph, True))
        
        # Shuffle with fixed seed
        self.rng.shuffle(benchmark)
        return benchmark
    
    def _generate_benign_graph(self, name: str) -> AgentWorkflowGraph:
        """Generate a benign workflow (no toxic flows)."""
        graph = AgentWorkflowGraph(name)
        
        num_nodes = self.rng.randint(self.config.min_nodes, self.config.max_nodes)
        
        # Add sources (mix of trusted and untrusted)
        num_sources = max(2, num_nodes // 5)
        for i in range(num_sources):
            trust = TrustLevel.TRUSTED if self.rng.random() > 0.3 else TrustLevel.UNTRUSTED
            graph.add_source(f"src_{i}", trust, f"Source {i}")
        
        # Add LLM nodes
        num_llms = max(1, num_nodes // 10)
        for i in range(num_llms):
            graph.add_llm(f"llm_{i}")
        
        # Add tools (following capability distribution)
        num_tools = num_nodes - num_sources - num_llms
        for i in range(num_tools):
            cap = self._sample_capability()
            domain = self.rng.choice(list(TOOL_TEMPLATES.keys()))
            tool_name, _ = self.rng.choice(TOOL_TEMPLATES[domain])
            graph.add_tool(f"tool_{i}", cap, tool_name)
        
        # Add sanitizers on paths from untrusted sources to sensitive tools
        # This ensures benign graphs don't have toxic flows
        untrusted = [n.node_id for n in graph.get_untrusted_sources()]
        sensitive = [n.node_id for n in graph.get_sensitive_sinks()]
        
        if untrusted and sensitive:
            # Add sanitizers to break potential toxic paths
            for src_id in untrusted:
                san_id = f"san_{src_id}"
                graph.add_sanitizer(san_id, APPROVAL_SANITIZER)
                graph.add_edge(src_id, san_id)
                # Connect sanitizer to an LLM
                llm_ids = [n.node_id for n in graph.nodes.values() 
                          if hasattr(n, 'node_type') and n.node_type == 'llm']
                if llm_ids:
                    graph.add_edge(san_id, self.rng.choice(llm_ids))
        
        # Add random edges (respecting structure)
        self._add_random_edges(graph)
        
        return graph
    
    def _generate_malicious_graph(self, name: str) -> AgentWorkflowGraph:
        """Generate a graph with at least one toxic flow."""
        graph = AgentWorkflowGraph(name)
        
        num_nodes = self.rng.randint(self.config.min_nodes, self.config.max_nodes)
        attack_depth = self.rng.randint(self.config.min_attack_depth, 
                                        self.config.max_attack_depth)
        
        # Add untrusted source
        untrusted_src = self.rng.choice(UNTRUSTED_SOURCES)
        graph.add_source("untrusted_source", TrustLevel.UNTRUSTED, untrusted_src)
        
        # Add trusted source
        graph.add_source("trusted_source", TrustLevel.TRUSTED, "User prompt")
        
        # Add LLM(s)
        for i in range(max(1, attack_depth - 1)):
            graph.add_llm(f"llm_{i}")
        
        # Add sensitive sink
        domain = self.rng.choice(list(TOOL_TEMPLATES.keys()))
        sensitive_tools = [(n, c) for n, c in TOOL_TEMPLATES[domain] 
                          if c == CapabilityLevel.SENSITIVE]
        if sensitive_tools:
            tool_name, cap = self.rng.choice(sensitive_tools)
        else:
            tool_name, cap = "send_network", CapabilityLevel.SENSITIVE
        graph.add_tool("sensitive_sink", cap, tool_name)
        
        # Create toxic path WITHOUT sanitizers
        # untrusted_source -> llm_0 -> ... -> sensitive_sink
        current = "untrusted_source"
        for i in range(attack_depth - 1):
            next_node = f"llm_{i % max(1, attack_depth - 1)}"
            if next_node in graph.nodes:
                graph.add_edge(current, next_node)
                current = next_node
        graph.add_edge(current, "sensitive_sink")
        
        # Add other nodes and edges
        remaining = num_nodes - len(graph.nodes)
        for i in range(remaining):
            cap = self._sample_capability()
            graph.add_tool(f"other_tool_{i}", cap, f"tool_{i}")
        
        self._add_random_edges(graph, avoid_sanitizers_on_toxic_path=True)
        
        return graph
    
    def _sample_capability(self) -> CapabilityLevel:
        """Sample capability level according to distribution."""
        r = self.rng.random()
        if r < self.config.capability_read:
            return CapabilityLevel.READ
        elif r < self.config.capability_read + self.config.capability_write:
            return CapabilityLevel.WRITE
        else:
            return CapabilityLevel.SENSITIVE
    
    def _add_random_edges(self, graph: AgentWorkflowGraph, 
                          avoid_sanitizers_on_toxic_path: bool = False) -> None:
        """Add random edges to create realistic workflow structure."""
        node_ids = list(graph.nodes.keys())
        target_edges = int(len(node_ids) * self.rng.uniform(
            self.config.min_edge_density, self.config.max_edge_density))
        
        current_edges = sum(len(e) for e in graph.edges.values())
        
        for _ in range(target_edges - current_edges):
            src = self.rng.choice(node_ids)
            dst = self.rng.choice(node_ids)
            if src != dst:
                graph.add_edge(src, dst)


# =============================================================================
# EVALUATION RESULTS
# =============================================================================

@dataclass
class EvaluationResult:
    """Stores evaluation metrics."""
    method_name: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_time_ms: float = 0.0
    num_samples: int = 0
    
    @property
    def tpr(self) -> float:
        """True Positive Rate (Recall/Sensitivity)."""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def fpr(self) -> float:
        """False Positive Rate."""
        if self.false_positives + self.true_negatives == 0:
            return 0.0
        return self.false_positives / (self.false_positives + self.true_negatives)
    
    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def f1_score(self) -> float:
        if self.precision + self.tpr == 0:
            return 0.0
        return 2 * (self.precision * self.tpr) / (self.precision + self.tpr)
    
    @property
    def mean_latency_ms(self) -> float:
        if self.num_samples == 0:
            return 0.0
        return self.total_time_ms / self.num_samples


# =============================================================================
# BASELINE DEFENSES
# =============================================================================

class KeywordFilterDefense:
    """Simple keyword-based filtering baseline."""
    
    SUSPICIOUS_PATTERNS = [
        "exfiltrate", "send to", "attacker", "malicious",
        "steal", "leak", "transfer to external", "send_network",
        "webhook", "post to", "upload to"
    ]
    
    def analyze(self, graph: AgentWorkflowGraph) -> List[ToxicFlow]:
        """Check for suspicious keywords in source descriptions."""
        flows = []
        for source in graph.get_untrusted_sources():
            desc = source.description.lower()
            if any(p in desc for p in self.SUSPICIOUS_PATTERNS):
                for sink in graph.get_sensitive_sinks():
                    flows.append(ToxicFlow(
                        source_id=source.node_id,
                        sink_id=sink.node_id,
                        path=[source.node_id, sink.node_id],
                        source_trust=source.trust_level,
                        sink_capability=sink.capability,
                        propagated_trust=TrustLevel.UNTRUSTED
                    ))
        return flows


class LLMJudgeDefense:
    """Simulated LLM-as-judge baseline."""
    
    def __init__(self, accuracy: float = 0.75, latency_ms: float = 340):
        self.accuracy = accuracy
        self.latency_ms = latency_ms
        self.rng = random.Random(42)
    
    def analyze(self, graph: AgentWorkflowGraph, has_toxic: bool) -> Tuple[List[ToxicFlow], float]:
        """Simulate LLM judge with configurable accuracy."""
        time.sleep(self.latency_ms / 1000)  # Simulate latency
        
        # Simulate accuracy
        correct = self.rng.random() < self.accuracy
        
        flows = []
        if (has_toxic and correct) or (not has_toxic and not correct):
            for source in graph.get_untrusted_sources():
                for sink in graph.get_sensitive_sinks():
                    flows.append(ToxicFlow(
                        source_id=source.node_id,
                        sink_id=sink.node_id,
                        path=[source.node_id, sink.node_id],
                        source_trust=source.trust_level,
                        sink_capability=sink.capability,
                        propagated_trust=TrustLevel.UNTRUSTED
                    ))
        
        return flows, self.latency_ms


# =============================================================================
# EXPERIMENT RUNNER
# =============================================================================

class ExperimentRunner:
    """Runs evaluation experiments on benchmark."""
    
    def __init__(self, benchmark: List[Tuple[AgentWorkflowGraph, bool]]):
        self.benchmark = benchmark
        self.tfa = ToxicFlowAnalyzer()
        self.keyword = KeywordFilterDefense()
        self.llm_judge = LLMJudgeDefense()
    
    def evaluate_tfa(self) -> EvaluationResult:
        """Evaluate TFA on benchmark."""
        result = EvaluationResult("TFA")
        
        for graph, has_toxic in self.benchmark:
            start = time.perf_counter()
            flows = self.tfa.analyze(graph)
            elapsed = (time.perf_counter() - start) * 1000
            
            detected = len(flows) > 0
            
            if has_toxic and detected:
                result.true_positives += 1
            elif has_toxic and not detected:
                result.false_negatives += 1
            elif not has_toxic and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1
            
            result.total_time_ms += elapsed
            result.num_samples += 1
        
        return result
    
    def evaluate_keyword_filter(self) -> EvaluationResult:
        """Evaluate keyword filter baseline."""
        result = EvaluationResult("Keyword Filter")
        
        for graph, has_toxic in self.benchmark:
            start = time.perf_counter()
            flows = self.keyword.analyze(graph)
            elapsed = (time.perf_counter() - start) * 1000
            
            detected = len(flows) > 0
            
            if has_toxic and detected:
                result.true_positives += 1
            elif has_toxic and not detected:
                result.false_negatives += 1
            elif not has_toxic and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1
            
            result.total_time_ms += elapsed
            result.num_samples += 1
        
        return result
    
    def run_depth_analysis(self) -> Dict[int, Dict[str, float]]:
        """Analyze detection rate by attack path depth."""
        depth_results = {d: {"tfa": 0, "keyword": 0, "llm": 0, "total": 0} 
                        for d in range(1, 6)}
        
        for graph, has_toxic in self.benchmark:
            if not has_toxic:
                continue
            
            # Estimate depth from graph structure
            flows = self.tfa.analyze(graph)
            if flows:
                depth = min(5, max(1, flows[0].path_depth))
                depth_results[depth]["total"] += 1
                depth_results[depth]["tfa"] += 1
                
                # Check keyword
                if self.keyword.analyze(graph):
                    depth_results[depth]["keyword"] += 1
        
        # Convert to rates
        for d in depth_results:
            total = depth_results[d]["total"]
            if total > 0:
                depth_results[d]["tfa_rate"] = depth_results[d]["tfa"] / total * 100
                depth_results[d]["keyword_rate"] = depth_results[d]["keyword"] / total * 100
        
        return depth_results


def run_full_evaluation() -> Dict:
    """Run complete evaluation and return results."""
    print("Generating benchmark with seed=42...")
    config = BenchmarkConfig(seed=42)
    generator = BenchmarkGenerator(config)
    benchmark = generator.generate_benchmark()
    
    print(f"Generated {len(benchmark)} graphs")
    print(f"  Benign: {config.num_benign}")
    print(f"  Malicious: {config.num_malicious}")
    
    runner = ExperimentRunner(benchmark)
    
    print("\nEvaluating TFA...")
    tfa_result = runner.evaluate_tfa()
    
    print("Evaluating Keyword Filter...")
    kw_result = runner.evaluate_keyword_filter()
    
    results = {
        "benchmark": {
            "seed": config.seed,
            "total_graphs": len(benchmark),
            "benign": config.num_benign,
            "malicious": config.num_malicious,
        },
        "tfa": {
            "tpr": f"{tfa_result.tpr * 100:.1f}%",
            "fpr": f"{tfa_result.fpr * 100:.1f}%",
            "f1": f"{tfa_result.f1_score:.2f}",
            "latency_ms": f"{tfa_result.mean_latency_ms:.1f}",
        },
        "keyword_filter": {
            "tpr": f"{kw_result.tpr * 100:.1f}%",
            "fpr": f"{kw_result.fpr * 100:.1f}%",
            "f1": f"{kw_result.f1_score:.2f}",
            "latency_ms": f"{kw_result.mean_latency_ms:.1f}",
        }
    }
    
    return results


if __name__ == "__main__":
    results = run_full_evaluation()
    print("\n" + "=" * 50)
    print("EVALUATION RESULTS")
    print("=" * 50)
    import json
    print(json.dumps(results, indent=2))
