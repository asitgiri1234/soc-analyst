"""The role model, kept separate from the HTTP layer that enforces it.

Roles are ranked rather than treated as a flat set, because the three tiers
nest: everything a VIEWER may do, an ANALYST may do too.

    VIEWER   read security data
    ANALYST  + create and modify security data, investigate incidents
    ADMIN    + manage users, roles and the audit trail

``is_superuser`` on a user is deliberately *not* part of this ranking. It is a
separate break-glass flag, checked explicitly where it applies.
"""

from __future__ import annotations

from app.models.enums import UserRole

_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 0,
    UserRole.ANALYST: 10,
    UserRole.ADMIN: 20,
}


def rank(role: UserRole) -> int:
    """Position of a role in the hierarchy; higher outranks lower."""
    return _RANK[role]


def has_at_least(role: UserRole, minimum: UserRole) -> bool:
    """True when ``role`` sits at or above ``minimum`` in the hierarchy."""
    return rank(role) >= rank(minimum)


def can_read_security_data(role: UserRole) -> bool:
    return has_at_least(role, UserRole.VIEWER)


def can_write_security_data(role: UserRole) -> bool:
    return has_at_least(role, UserRole.ANALYST)


def can_manage_users(role: UserRole) -> bool:
    return has_at_least(role, UserRole.ADMIN)
