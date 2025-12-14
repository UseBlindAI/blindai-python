"""RBAC stub for SDK-only mode."""

from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class Permission:
    """Permission stub."""
    name: str
    resource: str = "*"
    actions: Set[str] = field(default_factory=lambda: {"*"})


@dataclass  
class Role:
    """Role stub."""
    name: str
    permissions: List[Permission] = field(default_factory=list)


@dataclass
class UserContext:
    """User context for RBAC checks.
    
    In SDK-only mode, this is passed to the API for server-side enforcement.
    """
    user_id: str
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
