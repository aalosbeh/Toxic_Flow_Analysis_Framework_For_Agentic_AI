"""
TFA Experimental Evaluation Framework
=====================================
Benchmark generation and evaluation for Toxic Flow Analysis.

Generates synthetic agent workflow graphs based on AgentDojo patterns
and evaluates TFA detection performance.

Metrics:
- True Positive Rate (TPR) / Detection Rate
- False Positive Rate (FPR)
- F1 Score
- Analysis Latency
"""

import random
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
import statistics

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


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark generation."""
    num_benign: int = 200
    num_malicious: int = 300
    min_nodes: int = 15
    max_nodes: int = 50
    min_depth: int = 1
    max_depth: int = 5
    include_cycles: bool = True
    cycle_probability: float = 0.3
    sanitizer_probability: float = 0.2
    seed: int = 42


@dataclass
class EvaluationResult:
    """Results from benchmark evaluation."""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    latencies_ms: List[float] = field(default_factory=list)
    
    @property
    def tpr(self) -> float:
        """True Positive Rate (Recall/Sensitivity)."""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def fpr(self) -> float:
        """False Positive Rate."""
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0
    
    @property
    def precision(self) -> float:
        """Precision."""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        """F1 Score."""
        p, r = self.precision, self.tpr
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def mean_latency_ms(self) -> float:
        """Mean analysis latency in milliseconds."""
        return statistics.mean(self.latencies_ms) if self.latencies_ms else 0.0
    
    @property
    def p99_latency_ms(self) -> float:
        """99th percentile latency."""
        if not self.latencies_ms:
            return 0.0
        sorted_lat = sorted(self.latencies_ms)
        idx = int(0.99 * len(sorted_lat))
        return sorted_lat[min(idx, len(sorted_lat) - 1)]
    
    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "tpr": round(self.tpr * 100, 2),
            "fpr": round(self.fpr * 100, 2),
            "precision": round(self.precision * 100, 2),
            "f1_score": round(self.f1_score, 3),
            "mean_latency_ms": round(self.mean_latency_ms, 2),
            "p99_latency_ms": round(self.p99_latency_ms, 2)
        }


# Tool templates based on AgentDojo domains
TOOL_TEMPLATES = {
    "banking": [
        ("check_balance", CapabilityLevel.READ, "Check account balance"),
        ("transfer_funds", CapabilityLevel.SENSITIVE, "Transfer money between accounts"),
        ("get_transactions", CapabilityLevel.READ, "Get transaction history"),
        ("send_wire", CapabilityLevel.SENSITIVE, "Send wire transfer"),
        ("update_profile", CapabilityLevel.WRITE, "Update user profile"),
    ],
    "workspace": [
        ("read_email", CapabilityLevel.READ, "Read email messages"),
        ("send_email", CapabilityLevel.SENSITIVE, "Send email"),
        ("read_calendar", CapabilityLevel.READ, "Read calendar events"),
        ("create_event", CapabilityLevel.WRITE, "Create calendar event"),
        ("share_document", CapabilityLevel.SENSITIVE, "Share document externally"),
        ("search_files", CapabilityLevel.READ, "Search files"),
    ],
    "travel": [
        ("search_flights", CapabilityLevel.READ, "Search for flights"),
        ("book_flight", CapabilityLevel.SENSITIVE, "Book a flight"),
        ("check_reservation", CapabilityLevel.READ, "Check reservation status"),
        ("cancel_booking", CapabilityLevel.WRITE, "Cancel a booking"),
        ("process_payment", CapabilityLevel.SENSITIVE, "Process payment"),
    ],
    "developer": [
        ("read_file", CapabilityLevel.READ, "Read file contents"),
        ("write_file", CapabilityLevel.WRITE, "Write file contents"),
        ("execute_code", CapabilityLevel.SENSITIVE, "Execute code"),
        ("git_commit", CapabilityLevel.WRITE, "Git commit changes"),
        ("deploy_app", CapabilityLevel.SENSITIVE, "Deploy application"),
        ("send_request", CapabilityLevel.SENSITIVE, "Send network request"),
    ]
}

# Untrusted source templates
UNTRUSTED_SOURCES = [
    ("external_email", "Email from unknown sender"),
    ("web_content", "Content from external website"),
    ("api_response", "Response from third-party API"),
    ("user_upload", "User-uploaded file content"),
    ("chat_message", "Message from external chat"),
    ("github_issue", "GitHub issue content"),
    ("form_input", "External form submission"),
]


class BenchmarkGenerator:
    """
    Generates synthetic benchmark graphs for TFA evaluation.
    """
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        random.seed(config.seed)
    
    def generate_benchmark(self) -> List[Tuple[AgentWorkflowGraph, bool]]:
        """
        Generate complete benchmark suite.
        
        Returns:
            List of (graph, has_toxic_flow) pairs
        """
        benchmarks = []
        
        # Generate benign workflows
        for i in range(self.config.num_benign):
            graph = self._generate_benign_graph(f"benign_{i}")
            benchmarks.append((graph, False))
        
        # Generate malicious workflows with toxic flows
        for i in range(self.config.num_malicious):
            depth = random.randint(self.config.min_depth, self.config.max_depth)
            graph = self._generate_malicious_graph(f"malicious_{i}", depth)
            benchmarks.append((graph, True))
        
        random.shuffle(benchmarks)
        return benchmarks
    
    def _generate_benign_graph(self, name: str) -> AgentWorkflowGraph:
        """Generate a benign workflow without toxic flows."""
        graph = AgentWorkflowGraph(name=name)
        num_nodes = random.randint(self.config.min_nodes, self.config.max_nodes)
        
        # Add trusted source
        graph.add_source("user_prompt", TrustLevel.TRUSTED, "User instruction")
        
        # Optionally add untrusted source with sanitizer
        if random.random() < 0.5:
            src_template = random.choice(UNTRUSTED_SOURCES)
            graph.add_source(f"ext_{src_template[0]}", TrustLevel.UNTRUSTED, src_template[1])
            
            # Always add sanitizer for untrusted in benign graphs
            graph.add_sanitizer("sanitizer_0", APPROVAL_SANITIZER)
            graph.add_edge(f"ext_{src_template[0]}", "sanitizer_0")
        
        # Add LLM
        graph.add_llm("llm_main", "gpt-4")
        graph.add_edge("user_prompt", "llm_main")
        if f"ext_{UNTRUSTED_SOURCES[0][0]}" in graph.nodes:
            graph.add_edge("sanitizer_0", "llm_main")
        
        # Add tools from random domain
        domain = random.choice(list(TOOL_TEMPLATES.keys()))
        tools = random.sample(TOOL_TEMPLATES[domain], 
                             min(3, len(TOOL_TEMPLATES[domain])))
        
        prev_node = "llm_main"
        for i, (tool_name, cap, desc) in enumerate(tools):
            tool_id = f"tool_{i}_{tool_name}"
            graph.add_tool(tool_id, cap, tool_name, desc)
            
            # Sensitive tools only reachable from trusted paths
            if cap == CapabilityLevel.SENSITIVE:
                # Add HITL gate
                gate_id = f"hitl_{i}"
                graph.add_sanitizer(gate_id, SanitizerSpec(
                    name="hitl",
                    output_domain={"confirmed"},
                    safe_outputs={"confirmed"},
                    trust_elevation=lambda t: TrustLevel.TRUSTED
                ))
                graph.add_edge(prev_node, gate_id)
                graph.add_edge(gate_id, tool_id)
            else:
                graph.add_edge(prev_node, tool_id)
            
            # Some tools feed back to LLM
            if cap == CapabilityLevel.READ and random.random() < 0.5:
                graph.add_edge(tool_id, "llm_main")
            
            prev_node = tool_id
        
        # Optionally add cycles
        if self.config.include_cycles and random.random() < self.config.cycle_probability:
            tool_nodes = [n for n in graph.nodes if n.startswith("tool_")]
            if len(tool_nodes) >= 2:
                graph.add_edge(random.choice(tool_nodes), "llm_main")
        
        return graph
    
    def _generate_malicious_graph(self, name: str, depth: int) -> AgentWorkflowGraph:
        """Generate a workflow with an injected toxic flow."""
        graph = AgentWorkflowGraph(name=name)
        
        # Add trusted source
        graph.add_source("user_prompt", TrustLevel.TRUSTED, "User instruction")
        
        # Add untrusted source (injection point)
        src_template = random.choice(UNTRUSTED_SOURCES)
        untrusted_id = f"untrusted_{src_template[0]}"
        graph.add_source(untrusted_id, TrustLevel.UNTRUSTED, src_template[1])
        
        # Add LLM
        graph.add_llm("llm_main", "gpt-4")
        graph.add_edge("user_prompt", "llm_main")
        graph.add_edge(untrusted_id, "llm_main")  # No sanitizer - toxic flow start
        
        # Build path to sensitive sink
        domain = random.choice(list(TOOL_TEMPLATES.keys()))
        all_tools = TOOL_TEMPLATES[domain]
        
        # Ensure we have a sensitive tool as sink
        sensitive_tools = [t for t in all_tools if t[1] == CapabilityLevel.SENSITIVE]
        if not sensitive_tools:
            sensitive_tools = [("exfil_data", CapabilityLevel.SENSITIVE, "Exfiltrate data")]
        
        sink_tool = random.choice(sensitive_tools)
        
        # Build intermediate path
        prev_node = "llm_main"
        for i in range(depth - 1):
            intermediate = random.choice([t for t in all_tools if t[1] != CapabilityLevel.SENSITIVE])
            tool_id = f"tool_{i}_{intermediate[0]}"
            graph.add_tool(tool_id, intermediate[1], intermediate[0], intermediate[2])
            graph.add_edge(prev_node, tool_id)
            
            # Feed back to LLM to continue chain
            graph.add_edge(tool_id, "llm_main")
            prev_node = "llm_main"
        
        # Add sensitive sink (no sanitizer - completes toxic flow)
        sink_id = f"sink_{sink_tool[0]}"
        graph.add_tool(sink_id, sink_tool[1], sink_tool[0], sink_tool[2])
        graph.add_edge(prev_node, sink_id)
        
        # Maybe add some red herrings (benign paths)
        if random.random() < 0.5:
            safe_tool = random.choice([t for t in all_tools if t[1] == CapabilityLevel.READ])
            safe_id = f"safe_{safe_tool[0]}"
            graph.add_tool(safe_id, safe_tool[1], safe_tool[0], safe_tool[2])
            graph.add_edge("llm_main", safe_id)
        
        return graph


class BaselineDefense:
    """Base class for baseline defense mechanisms."""
    
    def analyze(self, graph: AgentWorkflowGraph) -> List[ToxicFlow]:
        raise NotImplementedError


class KeywordFilterDefense(BaselineDefense):
    """
    Simple keyword-based detection.
    Looks for suspicious patterns in node descriptions.
    """
    
    SUSPICIOUS_KEYWORDS = [
        "send", "transfer", "exfil", "external", "network",
        "deploy", "execute", "wire", "payment"
    ]
    
    def analyze(self, graph: AgentWorkflowGraph) -> List[ToxicFlow]:
        start = time.time()
        flows = []
        
        untrusted = [n for n in graph.nodes.values() 
                    if hasattr(n, 'trust_level') and n.trust_level == TrustLevel.UNTRUSTED]
        
        for node in graph.nodes.values():
            if hasattr(node, 'tool_name'):
                tool_lower = node.tool_name.lower()
                desc_lower = getattr(node, 'description', '').lower()
                
                for kw in self.SUSPICIOUS_KEYWORDS:
                    if kw in tool_lower or kw in desc_lower:
                        if untrusted:
                            flows.append(ToxicFlow(
                                source_id=untrusted[0].id,
                                sink_id=node.id,
                                path=[untrusted[0].id, "...", node.id],
                                propagated_trust=TrustLevel.UNTRUSTED,
                                description=f"Keyword match: {kw}"
                            ))
                        break
        
        return flows


class LLMJudgeDefense(BaselineDefense):
    """
    Simulated LLM-as-judge defense.
    Uses heuristics to simulate LLM evaluation latency and accuracy.
    """
    
    def __init__(self, accuracy: float = 0.75, latency_ms: float = 340):
        self.accuracy = accuracy
        self.latency_ms = latency_ms
    
    def analyze(self, graph: AgentWorkflowGraph) -> List[ToxicFlow]:
        # Simulate LLM latency
        time.sleep(self.latency_ms / 1000)
        
        flows = []
        
        # Check for untrusted-to-sensitive paths with probabilistic detection
        untrusted = graph.get_untrusted_sources()
        sensitive = graph.get_sensitive_sinks()
        
        for src in untrusted:
            for sink in sensitive:
                # Simple reachability check
                if self._is_reachable(graph, src.id, sink.id):
                    # Probabilistic detection based on accuracy
                    if random.random() < self.accuracy:
                        flows.append(ToxicFlow(
                            source_id=src.id,
                            sink_id=sink.id,
                            path=[src.id, "...", sink.id],
                            propagated_trust=TrustLevel.UNTRUSTED
                        ))
        
        return flows
    
    def _is_reachable(self, graph: AgentWorkflowGraph, 
                      start: str, end: str) -> bool:
        """BFS reachability check."""
        visited = set()
        queue = [start]
        
        while queue:
            node = queue.pop(0)
            if node == end:
                return True
            if node in visited:
                continue
            visited.add(node)
            queue.extend(graph.get_successors(node))
        
        return False


class ExperimentRunner:
    """
    Runs evaluation experiments comparing TFA against baselines.
    """
    
    def __init__(self, benchmark: List[Tuple[AgentWorkflowGraph, bool]]):
        self.benchmark = benchmark
        self.results = {}
    
    def evaluate_tfa(self) -> EvaluationResult:
        """Evaluate TFA on benchmark."""
        analyzer = ToxicFlowAnalyzer()
        result = EvaluationResult()
        
        for graph, has_toxic in self.benchmark:
            start = time.time()
            flows = analyzer.analyze(graph)
            latency = (time.time() - start) * 1000
            
            result.latencies_ms.append(latency)
            
            detected = len(flows) > 0
            
            if has_toxic and detected:
                result.true_positives += 1
            elif has_toxic and not detected:
                result.false_negatives += 1
            elif not has_toxic and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1
        
        self.results["tfa"] = result
        return result
    
    def evaluate_keyword_filter(self) -> EvaluationResult:
        """Evaluate keyword filter baseline."""
        defense = KeywordFilterDefense()
        result = EvaluationResult()
        
        for graph, has_toxic in self.benchmark:
            start = time.time()
            flows = defense.analyze(graph)
            latency = (time.time() - start) * 1000
            
            result.latencies_ms.append(latency)
            
            detected = len(flows) > 0
            
            if has_toxic and detected:
                result.true_positives += 1
            elif has_toxic and not detected:
                result.false_negatives += 1
            elif not has_toxic and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1
        
        self.results["keyword_filter"] = result
        return result
    
    def evaluate_llm_judge(self) -> EvaluationResult:
        """Evaluate LLM-as-judge baseline (simulated)."""
        defense = LLMJudgeDefense(accuracy=0.75)
        result = EvaluationResult()
        
        # Use smaller sample due to latency
        sample = random.sample(self.benchmark, min(100, len(self.benchmark)))
        
        for graph, has_toxic in sample:
            start = time.time()
            flows = defense.analyze(graph)
            latency = (time.time() - start) * 1000
            
            result.latencies_ms.append(latency)
            
            detected = len(flows) > 0
            
            if has_toxic and detected:
                result.true_positives += 1
            elif has_toxic and not detected:
                result.false_negatives += 1
            elif not has_toxic and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1
        
        self.results["llm_judge"] = result
        return result
    
    def run_depth_analysis(self) -> Dict[int, float]:
        """Analyze detection rate by path depth."""
        analyzer = ToxicFlowAnalyzer()
        depth_results = defaultdict(lambda: {"detected": 0, "total": 0})
        
        for graph, has_toxic in self.benchmark:
            if has_toxic:
                # Estimate depth from graph structure
                depth = self._estimate_depth(graph)
                
                flows = analyzer.analyze(graph)
                detected = len(flows) > 0
                
                depth_results[depth]["total"] += 1
                if detected:
                    depth_results[depth]["detected"] += 1
        
        return {
            depth: stats["detected"] / stats["total"] * 100 
            if stats["total"] > 0 else 0
            for depth, stats in sorted(depth_results.items())
        }
    
    def _estimate_depth(self, graph: AgentWorkflowGraph) -> int:
        """Estimate toxic flow depth from graph structure."""
        untrusted = graph.get_untrusted_sources()
        sensitive = graph.get_sensitive_sinks()
        
        if not untrusted or not sensitive:
            return 1
        
        # BFS to find shortest path
        visited = {untrusted[0].id: 0}
        queue = [(untrusted[0].id, 0)]
        
        while queue:
            node, depth = queue.pop(0)
            
            for succ in graph.get_successors(node):
                if succ not in visited:
                    visited[succ] = depth + 1
                    queue.append((succ, depth + 1))
        
        min_depth = min(
            (visited.get(s.id, 999) for s in sensitive),
            default=1
        )
        
        return min(max(min_depth, 1), 5)
    
    def run_ablation_study(self) -> Dict[str, EvaluationResult]:
        """Run ablation study removing components."""
        ablation_results = {}
        
        # Full TFA
        ablation_results["full"] = self.evaluate_tfa()
        
        # Without sanitizer modeling (treat all sanitizers as pass-through)
        analyzer_no_san = ToxicFlowAnalyzerNoSanitizer()
        ablation_results["no_sanitizer"] = self._evaluate_custom(analyzer_no_san)
        
        # Without trust lattice (binary trusted/untrusted)
        analyzer_no_lattice = ToxicFlowAnalyzerBinaryTrust()
        ablation_results["no_lattice"] = self._evaluate_custom(analyzer_no_lattice)
        
        # Path enumeration only
        analyzer_paths = ToxicFlowAnalyzerPathsOnly()
        ablation_results["paths_only"] = self._evaluate_custom(analyzer_paths)
        
        return ablation_results
    
    def _evaluate_custom(self, analyzer) -> EvaluationResult:
        """Evaluate custom analyzer variant."""
        result = EvaluationResult()
        
        for graph, has_toxic in self.benchmark:
            start = time.time()
            flows = analyzer.analyze(graph)
            latency = (time.time() - start) * 1000
            
            result.latencies_ms.append(latency)
            detected = len(flows) > 0
            
            if has_toxic and detected:
                result.true_positives += 1
            elif has_toxic and not detected:
                result.false_negatives += 1
            elif not has_toxic and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1
        
        return result
    
    def generate_report(self) -> str:
        """Generate evaluation report."""
        lines = [
            "=" * 70,
            "TOXIC FLOW ANALYSIS EVALUATION REPORT",
            "=" * 70,
            "",
            f"Benchmark size: {len(self.benchmark)} graphs",
            f"  - Benign: {sum(1 for _, t in self.benchmark if not t)}",
            f"  - Malicious: {sum(1 for _, t in self.benchmark if t)}",
            "",
            "-" * 70,
            "DETECTION PERFORMANCE",
            "-" * 70,
        ]
        
        for name, result in self.results.items():
            lines.extend([
                f"\n{name.upper()}:",
                f"  TPR (Detection Rate): {result.tpr * 100:.1f}%",
                f"  FPR (False Positive): {result.fpr * 100:.1f}%",
                f"  Precision: {result.precision * 100:.1f}%",
                f"  F1 Score: {result.f1_score:.3f}",
                f"  Mean Latency: {result.mean_latency_ms:.1f}ms",
                f"  P99 Latency: {result.p99_latency_ms:.1f}ms",
            ])
        
        return "\n".join(lines)


# Ablation study analyzer variants
class ToxicFlowAnalyzerNoSanitizer(ToxicFlowAnalyzer):
    """TFA variant that ignores sanitizers."""
    
    def _propagate_trust(self, input_trust: TrustLevel, node) -> TrustLevel:
        # Treat sanitizers as pass-through
        return input_trust


class ToxicFlowAnalyzerBinaryTrust(ToxicFlowAnalyzer):
    """TFA variant with binary trust (no PARTIAL level)."""
    
    def _propagate_trust(self, input_trust: TrustLevel, node) -> TrustLevel:
        from core import SanitizerNode
        
        if isinstance(node, SanitizerNode):
            # Sanitizers elevate directly to TRUSTED
            return TrustLevel.TRUSTED
        return input_trust


class ToxicFlowAnalyzerPathsOnly(ToxicFlowAnalyzer):
    """TFA variant that only checks path existence."""
    
    def _find_toxic_flows(self, graph, source, sink_ids):
        """Only check if path exists, ignore trust."""
        flows = []
        
        visited = set()
        queue = [(source.id, [source.id])]
        
        while queue:
            node_id, path = queue.pop(0)
            
            if node_id in visited:
                continue
            visited.add(node_id)
            
            if node_id in sink_ids:
                flows.append(ToxicFlow(
                    source_id=source.id,
                    sink_id=node_id,
                    path=path,
                    propagated_trust=TrustLevel.UNTRUSTED
                ))
            
            for succ in graph.get_successors(node_id):
                if succ not in visited:
                    queue.append((succ, path + [succ]))
        
        return flows


def run_full_evaluation():
    """Run complete evaluation suite and save results."""
    print("=" * 70)
    print("TFA EXPERIMENTAL EVALUATION")
    print("=" * 70)
    
    # Generate benchmark
    print("\n1. Generating benchmark...")
    config = BenchmarkConfig(
        num_benign=200,
        num_malicious=300,
        seed=42
    )
    generator = BenchmarkGenerator(config)
    benchmark = generator.generate_benchmark()
    print(f"   Generated {len(benchmark)} workflow graphs")
    
    # Run evaluation
    print("\n2. Running evaluations...")
    runner = ExperimentRunner(benchmark)
    
    print("   - Evaluating TFA...")
    tfa_result = runner.evaluate_tfa()
    
    print("   - Evaluating keyword filter...")
    kw_result = runner.evaluate_keyword_filter()
    
    print("   - Evaluating LLM-as-judge (simulated)...")
    llm_result = runner.evaluate_llm_judge()
    
    # Depth analysis
    print("\n3. Running depth analysis...")
    depth_results = runner.run_depth_analysis()
    
    # Generate report
    print("\n" + runner.generate_report())
    
    # Depth analysis results
    print("\n" + "-" * 70)
    print("DETECTION BY PATH DEPTH")
    print("-" * 70)
    for depth, rate in depth_results.items():
        print(f"  Depth {depth}: {rate:.1f}%")
    
    # Save results
    results_data = {
        "config": {
            "num_benign": config.num_benign,
            "num_malicious": config.num_malicious,
            "seed": config.seed
        },
        "results": {
            name: result.to_dict() 
            for name, result in runner.results.items()
        },
        "depth_analysis": depth_results
    }
    
    with open("evaluation_results.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print("\n" + "=" * 70)
    print("Results saved to evaluation_results.json")
    
    return results_data


if __name__ == "__main__":
    run_full_evaluation()
