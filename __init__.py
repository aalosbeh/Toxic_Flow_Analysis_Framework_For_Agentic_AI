"""
Toxic Flow Analysis (TFA) Framework

A Secure-by-Design framework for detecting and mitigating 
toxic flows in LLM-based autonomous agent systems.
"""

from tfa_framework.core import (
    TrustLevel,
    CapabilityLevel,
    SanitizerSpec,
    AgentWorkflowGraph,
    ToxicFlowAnalyzer,
    ToxicFlow,
    ProvenanceTracker,
    DynamicEnforcer,
    create_github_mcp_scenario,
    create_mitigated_github_scenario,
    BOOLEAN_SANITIZER,
    APPROVAL_SANITIZER,
    HITL_SANITIZER,
)

__version__ = "1.0.0"
__author__ = "AlSobeh, Shatnawi, Khamaiseh"
