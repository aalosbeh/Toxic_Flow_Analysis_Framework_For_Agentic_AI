# Toxic Flow Analysis (TFA) Framework

A Secure-by-Design framework for detecting and mitigating toxic flows in LLM-based autonomous agent systems.

## Paper

This implementation accompanies:

> **"Secure-by-Design Framework for Agentic AI: Mitigating Toxic Flows and Adversarial Exploits in Multi-Agent Ecosystems"**
> 
> AlSobeh, Shatnawi, Khamaiseh
> i-ETC 2026 Conference

## Important Notes

### Relationship to IFDS

This implementation draws conceptual inspiration from classical taint analysis, particularly the IFDS framework's source-to-sink reachability. However, **we do NOT implement full IFDS** with exploded supergraphs and distributive flow functions. Instead, we use a BFS-style traversal appropriate for agent workflow graphs where non-deterministic LLM behavior precludes precise dataflow assumptions.

**Complexity:** O(|V| × |E| × |D|) where |D| = |TrustLattice| = 3

### Benchmark Reproducibility

All benchmarks use **fixed parameters** for reproducibility:

- **Random seed:** 42
- **Graph sizes:** 15-50 nodes (uniform)
- **Edge density:** 1.5-2.5 edges per node
- **Capability distribution:** 40% R, 35% W, 25% S
- **Sanitizer placement:** 20% probability per edge
- **Attack depth:** 1-5 hops (uniform)

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
graph.add_source("external_api", TrustLevel.UNTRUSTED, "Third-party data")
graph.add_llm("llm")
graph.add_tool("send_email", CapabilityLevel.SENSITIVE, "send_email")

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
python main.py --demo all

# GitHub MCP exploit only
python main.py --demo github

# Mini benchmark
python main.py --demo benchmark
```

## Project Structure

```
code/
├── main.py                    # Demo runner
├── tfa_framework/
│   ├── __init__.py
│   └── core.py               # Core TFA implementation
├── experiments/
│   ├── __init__.py
│   └── evaluation.py         # Benchmark evaluation
├── datasets/
│   └── __init__.py
└── utils/
    └── __init__.py
```

## Citation

```bibtex
@inproceedings{alsobeh2026tfa,
  title={Secure-by-Design Framework for Agentic AI: Mitigating Toxic Flows 
         and Adversarial Exploits in Multi-Agent Ecosystems},
  author={AlSobeh, Anas and Shatnawi, Amani and Khamaiseh, Samer},
  booktitle={Proceedings of the i-ETC Conference},
  year={2026}
}
```

## License

Academic and research use. See paper for details.
