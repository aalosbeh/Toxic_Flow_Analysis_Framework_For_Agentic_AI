"""
TFA Framework - Lattice Definitions

Implements the formal lattice structures for Toxic Flow Analysis:
- Trust Lattice: L_T = ({U, P, T}, ⊑)
- Product Capability Lattice: L_C = L_Conf × L_Int × L_SE

The product lattice addresses the reviewer concern that a linear capability
ordering conflates orthogonal dimensions. A "read" tool with network egress
may pose greater exfiltration risk than a "write" tool with no external access.

Mathematical Foundation:
- The product of finite lattices forms a lattice
- Meet and join are computed component-wise
- This is a standard construction in abstract interpretation
"""

from enum import Enum, IntEnum
from dataclasses import dataclass
from typing import List, Tuple, Optional


# =============================================================================
# TRUST LATTICE: L_T = ({U, P, T}, ⊑)
# =============================================================================

class TrustLevel(IntEnum):
    """
    Trust Lattice ordering: U ⊑ P ⊑ T
    
    - UNTRUSTED (U): External, unverified data sources (bottom)
    - PARTIAL (P): Sanitized/validated data with bounded information
    - TRUSTED (T): Internal, verified data from trusted sources (top)
    
    Note: IntEnum allows direct comparison with < and >
    """
    UNTRUSTED = 0   # U - Bottom of lattice
    PARTIAL = 1     # P - Middle
    TRUSTED = 2     # T - Top of lattice
    
    def __repr__(self):
        return self.name[0]  # U, P, or T
    
    @staticmethod
    def join(levels: List['TrustLevel']) -> 'TrustLevel':
        """
        Join operation (⊔): Returns the LEAST trusted level.
        
        In security lattices, join is meet in the trust ordering because
        we want the most restrictive (least trusted) classification.
        This ensures conservative over-approximation.
        """
        if not levels:
            return TrustLevel.TRUSTED
        return TrustLevel(min(l.value for l in levels))
    
    @staticmethod
    def meet(levels: List['TrustLevel']) -> 'TrustLevel':
        """Meet operation (⊓): Returns the MOST trusted level."""
        if not levels:
            return TrustLevel.UNTRUSTED
        return TrustLevel(max(l.value for l in levels))
    
    @staticmethod
    def top() -> 'TrustLevel':
        return TrustLevel.TRUSTED
    
    @staticmethod
    def bottom() -> 'TrustLevel':
        return TrustLevel.UNTRUSTED
    
    @staticmethod
    def height() -> int:
        """Height of the lattice (for complexity analysis)."""
        return 3


# =============================================================================
# PRODUCT CAPABILITY LATTICE: L_C = L_Conf × L_Int × L_SE
# =============================================================================

class ConfidentialityLevel(IntEnum):
    """
    Confidentiality dimension: Does the tool access sensitive data?
    - LOW (L): No access to secrets, credentials, or private data
    - HIGH (H): Accesses secrets, credentials, private data, or PII
    """
    LOW = 0
    HIGH = 1
    
    def __repr__(self):
        return 'L' if self == ConfidentialityLevel.LOW else 'H'


class IntegrityLevel(IntEnum):
    """
    Integrity dimension: Does the tool modify state?
    - LOW (L): Read-only operations, no state changes
    - HIGH (H): Modifies files, databases, or system state
    """
    LOW = 0
    HIGH = 1
    
    def __repr__(self):
        return 'L' if self == IntegrityLevel.LOW else 'H'


class SideEffectLevel(IntEnum):
    """
    Side-effect dimension: Does the tool have external effects?
    - NONE (N): No external communication or effects
    - EXTERNAL (E): Network requests, external API calls, webhooks
    
    This dimension is CRITICAL for exfiltration detection:
    A tool can be (L, L, E) - low confidentiality, low integrity,
    but external side-effects make it an exfiltration vector.
    """
    NONE = 0
    EXTERNAL = 1
    
    def __repr__(self):
        return 'N' if self == SideEffectLevel.NONE else 'E'


@dataclass(frozen=True)
class ProductCapability:
    """
    Product Capability Lattice element: (Conf, Int, SE)
    
    The product ordering: (c1, i1, s1) ⊑ (c2, i2, s2) iff
    c1 ⊑ c2 ∧ i1 ⊑ i2 ∧ s1 ⊑ s2
    
    This decomposition properly separates orthogonal security dimensions,
    addressing the reviewer concern about conflating read/write with
    exfiltration risk.
    
    Examples:
    - git_read_file: (H, L, N) - high conf, low int, no external
    - send_network: (L, L, E) - low conf/int, but external effects
    - write_file: (L, H, N) - low conf, high int, no external
    - transfer_funds: (H, H, E) - high everything
    """
    conf: ConfidentialityLevel
    integrity: IntegrityLevel
    side_effects: SideEffectLevel
    
    def __le__(self, other: 'ProductCapability') -> bool:
        """Product ordering: component-wise ≤"""
        return (self.conf <= other.conf and 
                self.integrity <= other.integrity and
                self.side_effects <= other.side_effects)
    
    def __lt__(self, other: 'ProductCapability') -> bool:
        return self <= other and self != other
    
    def __repr__(self):
        return f"({self.conf!r},{self.integrity!r},{self.side_effects!r})"
    
    @property
    def is_sensitive(self) -> bool:
        """
        Backward-compatible sensitivity function σ(c, i, s).
        
        A tool is "sensitive" if:
        - High confidentiality (can read secrets), OR
        - High integrity (can modify important state), OR
        - External side-effects (can exfiltrate or communicate)
        
        This recovers the original "S" classification when any dimension is high.
        """
        return (self.conf == ConfidentialityLevel.HIGH or
                self.integrity == IntegrityLevel.HIGH or
                self.side_effects == SideEffectLevel.EXTERNAL)
    
    @staticmethod
    def join(caps: List['ProductCapability']) -> 'ProductCapability':
        """
        Join (⊔): Component-wise maximum.
        
        For security analysis, higher capability = more risk,
        so join gives the most permissive/risky classification.
        """
        if not caps:
            return ProductCapability.bottom()
        return ProductCapability(
            conf=ConfidentialityLevel(max(c.conf for c in caps)),
            integrity=IntegrityLevel(max(c.integrity for c in caps)),
            side_effects=SideEffectLevel(max(c.side_effects for c in caps))
        )
    
    @staticmethod
    def meet(caps: List['ProductCapability']) -> 'ProductCapability':
        """Meet (⊓): Component-wise minimum."""
        if not caps:
            return ProductCapability.top()
        return ProductCapability(
            conf=ConfidentialityLevel(min(c.conf for c in caps)),
            integrity=IntegrityLevel(min(c.integrity for c in caps)),
            side_effects=SideEffectLevel(min(c.side_effects for c in caps))
        )
    
    @staticmethod
    def top() -> 'ProductCapability':
        """Top element: (H, H, E) - maximum capability/risk"""
        return ProductCapability(
            ConfidentialityLevel.HIGH,
            IntegrityLevel.HIGH,
            SideEffectLevel.EXTERNAL
        )
    
    @staticmethod
    def bottom() -> 'ProductCapability':
        """Bottom element: (L, L, N) - minimum capability/risk"""
        return ProductCapability(
            ConfidentialityLevel.LOW,
            IntegrityLevel.LOW,
            SideEffectLevel.NONE
        )
    
    @staticmethod
    def height() -> int:
        """Height of product lattice = sum of component heights."""
        return 2 + 2 + 2  # Each binary lattice has height 2


# =============================================================================
# COMMON CAPABILITY PRESETS
# =============================================================================

# Backward-compatible mappings to old R/W/S classification
CAP_READ = ProductCapability(ConfidentialityLevel.LOW, IntegrityLevel.LOW, SideEffectLevel.NONE)
CAP_WRITE = ProductCapability(ConfidentialityLevel.LOW, IntegrityLevel.HIGH, SideEffectLevel.NONE)
CAP_SENSITIVE = ProductCapability(ConfidentialityLevel.HIGH, IntegrityLevel.HIGH, SideEffectLevel.EXTERNAL)

# More nuanced presets for common tool types
CAP_READ_SECRETS = ProductCapability(ConfidentialityLevel.HIGH, IntegrityLevel.LOW, SideEffectLevel.NONE)
CAP_NETWORK_SEND = ProductCapability(ConfidentialityLevel.LOW, IntegrityLevel.LOW, SideEffectLevel.EXTERNAL)
CAP_MODIFY_STATE = ProductCapability(ConfidentialityLevel.LOW, IntegrityLevel.HIGH, SideEffectLevel.NONE)
CAP_FULL_ACCESS = ProductCapability(ConfidentialityLevel.HIGH, IntegrityLevel.HIGH, SideEffectLevel.EXTERNAL)


# =============================================================================
# COMPOSITION ANALYSIS
# =============================================================================

def composition_risk(cap1: ProductCapability, cap2: ProductCapability) -> bool:
    """
    Check if composing two tools creates exfiltration risk.
    
    The critical pattern is:
    - Tool 1 has high confidentiality (can read secrets)
    - Tool 2 has external side-effects (can send data out)
    
    Neither tool alone may be "sensitive" under the linear model,
    but their composition enables exfiltration.
    
    This is exactly the GitHub MCP exploit pattern:
    - git_read_file: (H, L, N) - reads secrets, no network
    - send_network: (L, L, E) - no secrets, but sends data
    - Composition: secrets can flow out!
    """
    has_conf_source = cap1.conf == ConfidentialityLevel.HIGH or cap2.conf == ConfidentialityLevel.HIGH
    has_external_sink = cap1.side_effects == SideEffectLevel.EXTERNAL or cap2.side_effects == SideEffectLevel.EXTERNAL
    return has_conf_source and has_external_sink


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Trust lattice
    'TrustLevel',
    
    # Product capability lattice components
    'ConfidentialityLevel',
    'IntegrityLevel',
    'SideEffectLevel',
    'ProductCapability',
    
    # Presets
    'CAP_READ',
    'CAP_WRITE', 
    'CAP_SENSITIVE',
    'CAP_READ_SECRETS',
    'CAP_NETWORK_SEND',
    'CAP_MODIFY_STATE',
    'CAP_FULL_ACCESS',
    
    # Analysis
    'composition_risk',
]
