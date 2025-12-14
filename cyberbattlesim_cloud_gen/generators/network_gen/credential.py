
from dataclasses import dataclass
from enum import Enum


class CredentialLevel(Enum):
    """Privilege levels for service access"""
    NoAccess = 0
    LocalUser = 1
    Admin = 2
    System = 3
    MAXIMUM = 3

@dataclass
class CredentialGrant:
    """Represents a credential that one service has for accessing another"""
    source: str
    target: str
    credential_level: CredentialLevel
    credential_type: str
    is_cached: bool = False
    is_shared: bool = False
    can_pivot: bool = True
