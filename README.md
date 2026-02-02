# Toxic Flow Analysis (TFA) Framework v4.0

A Secure-by-Design framework for detecting toxic flows in LLM-based autonomous agent systems.

## What's New in v4.0

This version comprehensively addresses all reviewer feedback:

### 1. Product Capability Lattice
The original linear capability ordering (R ⊑ W ⊑ S) conflated orthogonal dimensions. v4.0 introduces a proper product lattice:

```
L_C = L_Conf × L_Int × L_SE

Where:
- L_Conf = {Low, High}     # Confidentiality impact
- L_Int = {Low, High}      # Integrity impact  
- L_SE = {None, External}  # Side-effects
```

**Why this matters:** A "read" tool with network egress may pose greater exfiltration risk than a "write" tool with no external access. The product lattice captures this.

### 2. Fixed-Point Algorithm
The v3 BFS with boolean flags didn't realize the multi-level lattice. v4.0 uses worklist-based fixed-point iteration with proper lattice operations:

- Maintains full lattice values (not boolean)
- Proper join (⊔) at each step
- Convergence guaranteed by finite lattice height
- Complexity: O(|V| · |E| · h) where h is lattice height

### 3. Explicit Soundness Guarantees
**Theorem 1:** If the workflow graph includes all possible information flows, TFA is sound—every actual toxic flow is detected.

**Limitations acknowledged:**
- Implicit edges from LLM non-determinism
- Dynamic tool discovery
- Requires complete graph specification

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from tfa_framework import (
    AgentWorkflowGraph, ToxicFlowAnalyzer,
    TrustLevel, ProductCapability,
    ConfidentialityLevel, IntegrityLevel, SideEffectLevel
)

# Create workflow graph
graph = AgentWorkflowGraph("my_agent")

# Add sources with trust labels
graph.add_source("external_api", TrustLevel.UNTRUSTED, "Third-party data")
graph.add_source("user_input", TrustLevel.TRUSTED, "User command")

# Add LLM
graph.add_llm("llm")

# Add tools with PRODUCT capabilities
graph.add_tool("read_secrets", ProductCapability(
    ConfidentialityLevel.HIGH,  # Reads sensitive data
    IntegrityLevel.LOW,         # No state changes
    SideEffectLevel.NONE        # No external effects
), "read_secrets")

graph.add_tool("send_network", ProductCapability(
    ConfidentialityLevel.LOW,   # No local secrets
    IntegrityLevel.LOW,         # No local state
    SideEffectLevel.EXTERNAL    # External communication!
), "send_network")

# Add edges
graph.add_edge("external_api", "llm")
graph.add_edge("llm", "read_secrets")
graph.add_edge("read_secrets", "llm")
graph.add_edge("llm", "send_network")

# Analyze with fixed-point algorithm
analyzer = ToxicFlowAnalyzer()
flows = analyzer.analyze(graph)

print(f"Fixed-point iterations: {analyzer.iterations}")
print(f"Toxic flows: {len(flows)}")
```

## Running Demos

```bash
python main.py
```

## Project Structure

```
code/
├── main.py                    # Demo runner
├── tfa_framework/
│   ├── __init__.py
│   ├── lattices.py           # NEW: Product lattice definitions
│   └── core.py               # Fixed-point analyzer
├── experiments/
├── datasets/
└── utils/
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
