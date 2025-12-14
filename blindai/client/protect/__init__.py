"""Protection methods for ToolGuard - check, check_batch, protect decorator."""

from .check import CheckMixin
from .batch import BatchMixin
from .decorator import DecoratorMixin
from .registration import RegistrationMixin


class ProtectMixin(CheckMixin, BatchMixin, DecoratorMixin, RegistrationMixin):
    """Mixin providing all protection methods for ToolGuard.
    
    Combines:
    - CheckMixin: check() method
    - BatchMixin: check_batch() method
    - DecoratorMixin: protect() decorator and call_tool()
    - RegistrationMixin: _register_tool_async()
    """
    pass


__all__ = [
    "ProtectMixin",
    "CheckMixin",
    "BatchMixin",
    "DecoratorMixin",
    "RegistrationMixin",
]
