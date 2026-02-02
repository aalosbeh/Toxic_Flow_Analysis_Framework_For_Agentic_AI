#!/usr/bin/env python3
"""
TFA Framework v4.0 - Main Runner

Demonstrates Toxic Flow Analysis with:
- Product capability lattice
- Fixed-point algorithm
- GitHub MCP exploit detection
"""

import sys
sys.path.insert(0, '.')

from tfa_framework.core import (
    AgentWorkflowGraph, ToxicFlowAnalyzer, ToxicFlow,
    TrustLevel, ProductCapability,
    ConfidentialityLevel, IntegrityLevel, SideEffectLevel,
    CAP_READ_SECRETS, CAP_NETWORK_SEND,
    create_github_mcp_scenario,
    create_mitigated_github_scenario,
    APPROVAL_SANITIZER
)
from tfa_framework.lattices import composition_risk


def demo_product_lattice():
    """Demonstrate product lattice vs linear lattice."""
    print("=" * 60)
    print("DEMO: Product Capability Lattice")
    print("=" * 60)
    
    # Create capabilities
    git_read = CAP_READ_SECRETS  # (H, L, N)
    send_net = CAP_NETWORK_SEND  # (L, L, E)
    
    print(f"\ngit_read_file capability: {git_read}")
    print(f"  - Confidentiality: HIGH (reads secrets)")
    print(f"  - Integrity: LOW (no state change)")
    print(f"  - Side-effects: NONE (no network)")
    print(f"  - Is sensitive? {git_read.is_sensitive}")
    
    print(f"\nsend_network capability: {send_net}")
    print(f"  - Confidentiality: LOW (no local secrets)")
    print(f"  - Integrity: LOW (no local state)")
    print(f"  - Side-effects: EXTERNAL (network egress)")
    print(f"  - Is sensitive? {send_net.is_sensitive}")
    
    print(f"\n⚠️  Composition risk check:")
    print(f"  composition_risk(git_read, send_net) = {composition_risk(git_read, send_net)}")
    print("  → Secrets can flow from git_read through send_network!")
    
    print("\nKey insight: Under linear R ⊑ W ⊑ S lattice, both tools might")
    print("be classified as 'Read' and appear safe. Product lattice captures")
    print("the exfiltration risk from their composition.")


def demo_github_exploit():
    """Demonstrate GitHub MCP exploit detection."""
    print("\n" + "=" * 60)
    print("DEMO: GitHub MCP Exploit Detection")
    print("=" * 60)
    
    # Vulnerable scenario
    print("\n1. Vulnerable Configuration:")
    print("-" * 40)
    
    vulnerable = create_github_mcp_scenario()
    analyzer = ToxicFlowAnalyzer()
    flows = analyzer.analyze(vulnerable)
    
    print(f"   Graph: {vulnerable}")
    print(f"   Fixed-point iterations: {analyzer.iterations}")
    print(f"   Analysis time: {analyzer.analysis_time_ms:.2f}ms")
    print(f"   Toxic flows detected: {len(flows)}")
    
    if flows:
        flow = flows[0]
        print(f"\n   Toxic Flow Details:")
        print(f"     Path: {' → '.join(flow.path)}")
        print(f"     Severity: {flow.severity}")
        print(f"     Source trust: {flow.source_trust.name}")
        print(f"     Sink capability: {flow.sink_capability}")
        print(f"     Propagated trust: {flow.propagated_trust.name}")
    
    # Mitigated scenario
    print("\n2. Mitigated Configuration (with sanitizer):")
    print("-" * 40)
    
    mitigated = create_mitigated_github_scenario()
    flows_mit = analyzer.analyze(mitigated)
    
    print(f"   Graph: {mitigated}")
    print(f"   Fixed-point iterations: {analyzer.iterations}")
    print(f"   Toxic flows detected: {len(flows_mit)}")
    
    if not flows_mit:
        print("   ✓ SUCCESS: Sanitizer blocks toxic flow!")
    else:
        print("   ✗ Toxic flow still present")


def demo_fixed_point():
    """Demonstrate fixed-point iteration on cyclic graph."""
    print("\n" + "=" * 60)
    print("DEMO: Fixed-Point Iteration on Cyclic Graph")
    print("=" * 60)
    
    # Create cyclic ReAct pattern
    graph = AgentWorkflowGraph("react_loop")
    
    graph.add_source("external_data", TrustLevel.UNTRUSTED, "External API response")
    graph.add_source("user_goal", TrustLevel.TRUSTED, "User objective")
    
    graph.add_llm("planner")
    graph.add_llm("executor")
    
    graph.add_tool("read_state", ProductCapability(
        ConfidentialityLevel.HIGH, IntegrityLevel.LOW, SideEffectLevel.NONE
    ), "read_state")
    graph.add_tool("write_state", ProductCapability(
        ConfidentialityLevel.LOW, IntegrityLevel.HIGH, SideEffectLevel.NONE
    ), "write_state")
    graph.add_tool("send_result", ProductCapability(
        ConfidentialityLevel.LOW, IntegrityLevel.LOW, SideEffectLevel.EXTERNAL
    ), "send_result")
    
    # Create cycle: planner → executor → read_state → planner (loop)
    graph.add_edge("external_data", "planner")
    graph.add_edge("user_goal", "planner")
    graph.add_edge("planner", "executor")
    graph.add_edge("executor", "read_state")
    graph.add_edge("read_state", "planner")  # Back edge creates cycle
    graph.add_edge("executor", "write_state")
    graph.add_edge("planner", "send_result")
    
    print(f"\n   Graph: {graph}")
    print(f"   Contains cycle: planner → executor → read_state → planner")
    
    analyzer = ToxicFlowAnalyzer()
    flows = analyzer.analyze(graph)
    
    print(f"\n   Fixed-point iterations: {analyzer.iterations}")
    print(f"   (Multiple iterations needed for cycle convergence)")
    print(f"   Toxic flows detected: {len(flows)}")
    
    for i, flow in enumerate(flows):
        print(f"\n   Flow {i+1}: {flow.severity} severity")
        print(f"     Path: {' → '.join(flow.path)}")


def demo_soundness_limitations():
    """Demonstrate soundness limitations."""
    print("\n" + "=" * 60)
    print("DEMO: Soundness Limitations")
    print("=" * 60)
    
    print("""
   TFA provides sound over-approximation ONLY IF the workflow graph
   includes all possible information flows (Theorem 1).
   
   Limitations that may cause FALSE NEGATIVES:
   
   1. IMPLICIT EDGES: LLM may invoke tools not modeled in graph
      → Solution: Conservative modeling of all possible tool calls
   
   2. DYNAMIC TOOL DISCOVERY: MCP allows runtime tool registration
      → Solution: Re-analyze after tool additions
   
   3. LLM NON-DETERMINISM: Same input may produce different tool sequences
      → Solution: Model all possible sequences (exponential worst case)
   
   These are FUNDAMENTAL limitations of static analysis applied to
   non-deterministic systems. TFA complements runtime enforcement
   systems like CaMeL and FIDES.
    """)


def main():
    print("=" * 60)
    print("TOXIC FLOW ANALYSIS (TFA) FRAMEWORK v4.0")
    print("AlSobeh, Shatnawi, Khamaiseh - i-ETC 2026")
    print("=" * 60)
    print("\nKey improvements in v4.0:")
    print("  - Product capability lattice (Conf × Int × SE)")
    print("  - Fixed-point algorithm (proper lattice semantics)")
    print("  - Explicit soundness guarantees")
    
    demo_product_lattice()
    demo_github_exploit()
    demo_fixed_point()
    demo_soundness_limitations()
    
    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
