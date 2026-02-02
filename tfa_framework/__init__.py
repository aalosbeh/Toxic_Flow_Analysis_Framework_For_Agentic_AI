"""
TFA Framework - Toxic Flow Analysis for Agentic AI Security

Version 4.0 - Comprehensive revision addressing all reviewer feedback:
- Product capability lattice (not linear ordering)
- Fixed-point algorithm (proper lattice semantics)
- Explicit soundness guarantees
"""

from .lattices import *
from .core import *

__version__ = "4.0.0"
__author__ = "AlSobeh, Shatnawi, Khamaiseh"
