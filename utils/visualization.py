"""
Visualization Utilities for TFA
================================
Generate visual representations of agent workflow graphs
and toxic flow analysis results.
"""

import json
from typing import List, Dict, Any, Optional


def graph_to_mermaid(graph, flows: List = None, title: str = None) -> str:
    """
    Convert AgentWorkflowGraph to Mermaid diagram syntax.
    
    Args:
        graph: AgentWorkflowGraph instance
        flows: Optional list of ToxicFlow objects to highlight
        title: Optional diagram title
        
    Returns:
        Mermaid diagram string
    """
    lines = ["graph TD"]
    
    if title:
        lines.insert(0, f"---\ntitle: {title}\n---")
    
    # Track toxic flow paths for highlighting
    toxic_edges = set()
    if flows:
        for flow in flows:
            for i in range(len(flow.path) - 1):
                toxic_edges.add((flow.path[i], flow.path[i + 1]))
    
    # Add nodes with styling
    for node_id, node in graph.nodes.items():
        if hasattr(node, 'trust_level'):
            trust = node.trust_level.name
            if trust == "UNTRUSTED":
                lines.append(f'    {node_id}["{node_id}<br/>⚠️ UNTRUSTED"]')
                lines.append(f'    style {node_id} fill:#ffcccc,stroke:#cc0000')
            elif trust == "TRUSTED":
                lines.append(f'    {node_id}["{node_id}<br/>✓ TRUSTED"]')
                lines.append(f'    style {node_id} fill:#ccffcc,stroke:#00cc00')
            else:
                lines.append(f'    {node_id}["{node_id}<br/>◐ PARTIAL"]')
                lines.append(f'    style {node_id} fill:#ffffcc,stroke:#cccc00')
        
        elif hasattr(node, 'capability_level'):
            cap = node.capability_level.name
            tool_name = getattr(node, 'tool_name', node_id)
            if cap == "SENSITIVE":
                lines.append(f'    {node_id}["{tool_name}<br/>🔴 SENSITIVE"]')
                lines.append(f'    style {node_id} fill:#ff9999,stroke:#cc0000')
            elif cap == "WRITE":
                lines.append(f'    {node_id}["{tool_name}<br/>🟡 WRITE"]')
                lines.append(f'    style {node_id} fill:#ffcc99,stroke:#cc6600')
            else:
                lines.append(f'    {node_id}["{tool_name}<br/>🟢 READ"]')
                lines.append(f'    style {node_id} fill:#99ff99,stroke:#006600')
        
        elif node.node_type.name == "LLM":
            lines.append(f'    {node_id}(("{node_id}<br/>🤖 LLM"))')
            lines.append(f'    style {node_id} fill:#99ccff,stroke:#0066cc')
        
        elif node.node_type.name == "SANITIZER":
            lines.append(f'    {node_id}{{{{{node_id}<br/>🛡️ SANITIZER}}}}')
            lines.append(f'    style {node_id} fill:#cc99ff,stroke:#6600cc')
        
        else:
            lines.append(f'    {node_id}["{node_id}"]')
    
    # Add edges
    for edge in graph.edges:
        if (edge.source_id, edge.target_id) in toxic_edges:
            lines.append(f'    {edge.source_id} -->|TOXIC| {edge.target_id}')
            lines.append(f'    linkStyle {len([e for e in graph.edges if (e.source_id, e.target_id) in toxic_edges]) - 1} stroke:#ff0000,stroke-width:3px')
        else:
            lines.append(f'    {edge.source_id} --> {edge.target_id}')
    
    return "\n".join(lines)


def graph_to_dot(graph, flows: List = None) -> str:
    """
    Convert AgentWorkflowGraph to Graphviz DOT format.
    
    Args:
        graph: AgentWorkflowGraph instance
        flows: Optional list of ToxicFlow objects to highlight
        
    Returns:
        DOT format string
    """
    lines = [
        "digraph G {",
        "    rankdir=TB;",
        "    node [fontname=\"Helvetica\"];",
        "    edge [fontname=\"Helvetica\"];"
    ]
    
    # Track toxic flow paths
    toxic_edges = set()
    if flows:
        for flow in flows:
            for i in range(len(flow.path) - 1):
                toxic_edges.add((flow.path[i], flow.path[i + 1]))
    
    # Add nodes
    for node_id, node in graph.nodes.items():
        attrs = []
        
        if hasattr(node, 'trust_level'):
            trust = node.trust_level.name
            if trust == "UNTRUSTED":
                attrs.extend(['shape=box', 'fillcolor="#ffcccc"', 'style=filled'])
            elif trust == "TRUSTED":
                attrs.extend(['shape=box', 'fillcolor="#ccffcc"', 'style=filled'])
            else:
                attrs.extend(['shape=box', 'fillcolor="#ffffcc"', 'style=filled'])
        
        elif hasattr(node, 'capability_level'):
            cap = node.capability_level.name
            if cap == "SENSITIVE":
                attrs.extend(['shape=box', 'fillcolor="#ff9999"', 'style=filled'])
            elif cap == "WRITE":
                attrs.extend(['shape=box', 'fillcolor="#ffcc99"', 'style=filled'])
            else:
                attrs.extend(['shape=box', 'fillcolor="#99ff99"', 'style=filled'])
        
        elif node.node_type.name == "LLM":
            attrs.extend(['shape=ellipse', 'fillcolor="#99ccff"', 'style=filled'])
        
        elif node.node_type.name == "SANITIZER":
            attrs.extend(['shape=diamond', 'fillcolor="#cc99ff"', 'style=filled'])
        
        attr_str = ", ".join(attrs) if attrs else ""
        lines.append(f'    "{node_id}" [{attr_str}];')
    
    # Add edges
    for edge in graph.edges:
        if (edge.source_id, edge.target_id) in toxic_edges:
            lines.append(f'    "{edge.source_id}" -> "{edge.target_id}" [color=red, penwidth=2];')
        else:
            lines.append(f'    "{edge.source_id}" -> "{edge.target_id}";')
    
    lines.append("}")
    return "\n".join(lines)


def generate_latex_table(results: Dict[str, Any]) -> str:
    """
    Generate LaTeX table from evaluation results.
    
    Args:
        results: Dictionary with evaluation results
        
    Returns:
        LaTeX table string
    """
    lines = [
        r"\begin{table}[htbp]",
        r"\caption{Detection Performance Comparison}",
        r"\label{tab:results}",
        r"\centering",
        r"\begin{tabular}{@{}lcccc@{}}",
        r"\toprule",
        r"\textbf{Method} & \textbf{TPR} & \textbf{FPR} & \textbf{F1} & \textbf{Latency} \\",
        r"\midrule"
    ]
    
    for method, data in results.items():
        tpr = f"{data.get('tpr', 0):.1f}\\%"
        fpr = f"{data.get('fpr', 0):.1f}\\%"
        f1 = f"{data.get('f1_score', 0):.2f}"
        latency = f"{data.get('mean_latency_ms', 0):.0f}ms"
        
        method_name = method.replace("_", " ").title()
        lines.append(f"{method_name} & {tpr} & {fpr} & {f1} & {latency} \\\\")
    
    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}"
    ])
    
    return "\n".join(lines)


def generate_tikz_figure(graph, flows: List = None) -> str:
    """
    Generate TikZ figure code for LaTeX.
    
    Args:
        graph: AgentWorkflowGraph instance
        flows: Optional list of ToxicFlow objects to highlight
        
    Returns:
        TikZ code string
    """
    lines = [
        r"\begin{figure}[htbp]",
        r"\centering",
        r"\begin{tikzpicture}[",
        r"    node distance=1.5cm,",
        r"    source/.style={rectangle, draw, fill=red!20, minimum width=2cm},",
        r"    trusted/.style={rectangle, draw, fill=green!20, minimum width=2cm},",
        r"    llm/.style={ellipse, draw, fill=blue!20},",
        r"    tool/.style={rectangle, draw, fill=orange!20, minimum width=2cm},",
        r"    sanitizer/.style={diamond, draw, fill=purple!20},",
        r"    arrow/.style={->, >=Stealth, thick},",
        r"    toxic/.style={->, >=Stealth, thick, red, dashed}",
        r"]"
    ]
    
    # Position nodes (simplified layout)
    y_pos = 0
    x_pos = 0
    node_positions = {}
    
    # Sources at top
    sources = [n for n in graph.nodes.values() if hasattr(n, 'trust_level')]
    for i, node in enumerate(sources):
        style = "trusted" if node.trust_level.name == "TRUSTED" else "source"
        node_positions[node.id] = (i * 3, 0)
        lines.append(f"\\node[{style}] ({node.id}) at ({i * 3}, 0) {{{node.id}}};")
    
    # LLMs in middle
    llms = [n for n in graph.nodes.values() if n.node_type.name == "LLM"]
    for i, node in enumerate(llms):
        node_positions[node.id] = (1.5, -2)
        lines.append(f"\\node[llm] ({node.id}) at (1.5, -2) {{{node.id}}};")
    
    # Tools at bottom
    tools = [n for n in graph.nodes.values() if hasattr(n, 'capability_level')]
    for i, node in enumerate(tools):
        node_positions[node.id] = (i * 2, -4)
        tool_name = getattr(node, 'tool_name', node.id)
        lines.append(f"\\node[tool] ({node.id}) at ({i * 2}, -4) {{{tool_name}}};")
    
    # Edges
    toxic_edges = set()
    if flows:
        for flow in flows:
            for i in range(len(flow.path) - 1):
                toxic_edges.add((flow.path[i], flow.path[i + 1]))
    
    for edge in graph.edges:
        style = "toxic" if (edge.source_id, edge.target_id) in toxic_edges else "arrow"
        lines.append(f"\\draw[{style}] ({edge.source_id}) -- ({edge.target_id});")
    
    lines.extend([
        r"\end{tikzpicture}",
        r"\caption{Agent Workflow Graph}",
        r"\label{fig:workflow}",
        r"\end{figure}"
    ])
    
    return "\n".join(lines)


def results_to_json(results: Dict, filename: str) -> None:
    """Save results to JSON file."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {filename}")


def print_flow_report(flows: List, verbose: bool = True) -> str:
    """
    Generate human-readable report of detected toxic flows.
    
    Args:
        flows: List of ToxicFlow objects
        verbose: Include detailed information
        
    Returns:
        Report string
    """
    if not flows:
        return "No toxic flows detected. System appears secure."
    
    lines = [
        "=" * 60,
        f"TOXIC FLOW ANALYSIS REPORT",
        f"Detected {len(flows)} potential vulnerability(ies)",
        "=" * 60
    ]
    
    for i, flow in enumerate(flows, 1):
        lines.extend([
            f"\n[{i}] {flow.severity} SEVERITY",
            f"    Source: {flow.source_id}",
            f"    Sink: {flow.sink_id}",
            f"    Path: {' → '.join(flow.path)}",
            f"    Trust: {flow.propagated_trust.name}"
        ])
        
        if verbose and flow.description:
            lines.append(f"    Description: {flow.description}")
    
    lines.extend([
        "\n" + "=" * 60,
        "RECOMMENDATIONS:",
        "  1. Add sanitizer nodes between untrusted sources and LLM",
        "  2. Implement HITL gates before sensitive tool invocations",
        "  3. Apply capability restrictions based on context trust",
        "  4. Enable runtime provenance tracking",
        "=" * 60
    ])
    
    return "\n".join(lines)


if __name__ == "__main__":
    # Demo visualization
    import sys
    sys.path.insert(0, '..')
    from tfa_framework.core import create_github_mcp_scenario, ToxicFlowAnalyzer
    
    graph = create_github_mcp_scenario()
    analyzer = ToxicFlowAnalyzer()
    flows = analyzer.analyze(graph)
    
    print("Mermaid Diagram:")
    print(graph_to_mermaid(graph, flows, "GitHub MCP Exploit"))
    print("\n" + "=" * 60 + "\n")
    
    print("Flow Report:")
    print(print_flow_report(flows))
