# Vendored from MHBench (github.com/bsinger98/MHBench), MIT © 2025 Brian Singer.
# Only src.*->mhbench.* import prefixes changed. License: third_party/mhbench/LICENSE.
"""
Virtual attacker models for attack path specifications.

This module contains models for representing external attackers that are not part
of the network topology but are needed for attack path modeling.
"""

from mhbench.models.network import Host
from mhbench.models.enums import OSType


def create_default_external_attacker() -> Host:
    """Create a default external attacker."""
    return Host(name="external_attacker", os_type=OSType.KALI_LINUX)
