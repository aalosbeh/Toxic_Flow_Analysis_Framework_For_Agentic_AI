"""
Toxic Flow Analysis (TFA) Framework
====================================

A comprehensive framework for detecting and mitigating toxic flows
in LLM-based autonomous agent systems.

Components:
- tfa_framework: Core analysis engine
- experiments: Evaluation and benchmarking
- datasets: Attack patterns and workflow templates
- utils: Helper functions and visualizations

Usage:
    from tfa_framework.core import AgentWorkflowGraph, ToxicFlowAnalyzer
    
    graph = AgentWorkflowGraph("my_agent")
    graph.add_source("user", TrustLevel.TRUSTED, "User prompt")
    graph.add_source("email", TrustLevel.UNTRUSTED, "External email")
    graph.add_llm("llm")
    graph.add_tool("send", CapabilityLevel.SENSITIVE, "send_email")
    
    graph.add_edge("user", "llm")
    graph.add_edge("email", "llm")
    graph.add_edge("llm", "send")
    
    analyzer = ToxicFlowAnalyzer()
    flows = analyzer.analyze(graph)

Authors: AlSobeh, Shatnawi, Khamaiseh
Target: i-ETC 2026 Conference
"""

__version__ = "1.0.0"
__author__ = "AlSobeh, Shatnawi, Khamaiseh"

from tfa_framework.core import (
    TrustLevel,
    CapabilityLevel,
    AgentWorkflowGraph,
    ToxicFlowAnalyzer,
    ToxicFlow,
    ProvenanceTracker,
    DynamicEnforcer,
    SanitizerSpec,
    BOOLEAN_SANITIZER,
    APPROVAL_SANITIZER,
    HITL_SANITIZER,
    create_github_mcp_scenario,
    create_mitigated_github_scenario
)

__all__ = [
    "TrustLevel",
    "CapabilityLevel", 
    "AgentWorkflowGraph",
    "ToxicFlowAnalyzer",
    "ToxicFlow",
    "ProvenanceTracker",
    "DynamicEnforcer",
    "SanitizerSpec",
    "BOOLEAN_SANITIZER",
    "APPROVAL_SANITIZER",
    "HITL_SANITIZER",
    "create_github_mcp_scenario",
    "create_mitigated_github_scenario"
]
