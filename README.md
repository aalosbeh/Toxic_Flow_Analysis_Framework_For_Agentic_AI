# Toxic Flow Analysis (TFA) Framework

A Secure-by-Design framework for detecting and mitigating toxic flows in LLM-based autonomous agent systems.

## Overview

This implementation accompanies the paper:

> **"Secure-by-Design Framework for Agentic AI: Mitigating Toxic Flows and Adversarial Exploits in Multi-Agent Ecosystems"**
> 
> AlSobeh, Shatnawi, Khamaiseh
> i-ETC 2026 Conference

## Features

- **Static Toxic Flow Analysis**: Graph-based reachability analysis with trust propagation
- **Trust/Capability Lattices**: Formal information-flow control semantics
- **Sanitizer Specifications**: Verifiable trust elevation mechanisms
- **Provenance Tracking**: Cryptographic metadata for runtime enforcement
- **Benchmark Suite**: Synthetic evaluation based on AgentDojo patterns

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from tfa_framework.core import (
    AgentWorkflowGraph, ToxicFlowAnalyzer,
    TrustLevel, CapabilityLevel
)

# Create workflow graph
graph = AgentWorkflowGraph("my_agent")

# Add sources
graph.add_source("user_prompt", TrustLevel.TRUSTED, "User input")
graph.add_source("external_api", TrustLevel.UNTRUSTED, "Third-party data")

# Add LLM and tools
graph.add_llm("llm")
graph.add_tool("send_email", CapabilityLevel.SENSITIVE, "send_email")

# Connect workflow
graph.add_edge("user_prompt", "llm")
graph.add_edge("external_api", "llm")
graph.add_edge("llm", "send_email")

# Analyze
analyzer = ToxicFlowAnalyzer()
flows = analyzer.analyze(graph)

if flows:
    print(f"Detected {len(flows)} toxic flow(s)!")
    for flow in flows:
        print(f"  Path: {' -> '.join(flow.path)}")
```

## Running Demos

```bash
# Run all demonstrations
python main.py

# Run specific demo (1-5)
python main.py --demo 2

# Full benchmark evaluation
python main.py --full-eval

# Export results and visualizations
python main.py --export
```

## Project Structure

```
code/
├── main.py                    # Main runner script
├── tfa_framework/
│   ├── __init__.py
│   └── core.py               # Core TFA implementation
├── experiments/
│   ├── __init__.py
│   └── evaluation.py         # Benchmark evaluation
├── datasets/
│   ├── __init__.py
│   └── attack_patterns.py    # Attack pattern database
└── utils/
    ├── __init__.py
    └── visualization.py      # Diagram generation
```

## Core Components

### TrustLevel Lattice
- `UNTRUSTED` (U): External, unverified data
- `PARTIAL` (P): Sanitized/validated data
- `TRUSTED` (T): Internal, verified data

### CapabilityLevel Lattice
- `READ`: Read-only operations
- `WRITE`: State-modifying operations
- `SENSITIVE`: Exfiltration-capable operations

### Key Classes
- `AgentWorkflowGraph`: Represents agent workflow as directed graph
- `ToxicFlowAnalyzer`: Static analysis engine
- `ProvenanceTracker`: Runtime metadata tracking
- `DynamicEnforcer`: Runtime policy enforcement
- `SanitizerSpec`: Formal sanitizer specification

## Evaluation Metrics

The framework is evaluated on synthetic benchmarks measuring:
- **TPR** (True Positive Rate): Detection rate
- **FPR** (False Positive Rate): False alarm rate
- **F1 Score**: Harmonic mean of precision and recall
- **Latency**: Analysis time in milliseconds

## Citation

```bibtex
@inproceedings{alsobeh2026tfa,
  title={Secure-by-Design Framework for Agentic AI: Mitigating Toxic Flows and Adversarial Exploits in Multi-Agent Ecosystems},
  author={AlSobeh, Anas and Shatnawi, Amani and Khamaiseh, Samer},
  booktitle={Proceedings of the i-ETC Conference},
  year={2026}
}
```

## License

This code is provided for academic and research purposes accompanying the published paper.

## Acknowledgments

- AgentDojo benchmark (Debenedetti et al., NeurIPS 2024)
- InjecAgent (Zhan et al., ACL 2024)
- FIDES framework (Costa & Köpf, 2025)
- CaMeL architecture (Wu et al., 2025)
