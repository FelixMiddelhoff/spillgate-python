"""The limits a decoder enforces (SPEC section 3)."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidLimitsError

__all__ = [
    "DEFAULT_MAX_LAYERS",
    "DEFAULT_MAX_RATIO",
    "DEFAULT_RATIO_GRACE",
    "HARD_MAX_LAYERS",
    "HARD_MAX_RATIO",
    "Limits",
]

DEFAULT_MAX_LAYERS = 5
DEFAULT_MAX_RATIO = 1000
DEFAULT_RATIO_GRACE = 64 * 1024

HARD_MAX_LAYERS = 16
HARD_MAX_RATIO = 2**31 - 1
_MAX_INT64 = 2**63 - 1


def _integer(name: str, value: object, low: int, high: int) -> int:
    """Return ``value`` if it is a real integer in ``low..high``, else raise.

    ``bool`` is rejected on purpose (``True`` is an ``int`` in Python), and so
    are floats, strings and everything else that is not an ``int``.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidLimitsError(f"{name} must be an integer, got {type(value).__name__}")
    if not low <= value <= high:
        raise InvalidLimitsError(f"{name} must be in {low}..{high}, got {value}")
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class Limits:
    """What a decoder enforces. Immutable; validated when created (SG-R-LIM-08, LIM-09).

    Args:
        max_output: bytes one layer may produce, ``1 .. 2**63-1``. Required: there
            is no default and no way to ask for "unlimited" (SG-R-LIM-01).
        max_layers: longest chain of non-identity encodings, ``1 .. 16``. ``None``
            means the default, 5. An explicit 0 is invalid (SG-R-LIM-03).
        max_ratio: output bytes per input byte the codec consumed, ``1 .. 2**31-1``.
            ``None`` means the default, 1000. No number switches the check off
            (SG-R-LIM-04).
        ratio_grace: output size below which the ratio is not checked. ``None``
            means the default, 64 KiB. ``0`` checks from the first byte.
        max_input: optional cap on the compressed bytes taken from the source,
            ``1 .. 2**63-1``. ``None`` means no cap; ``0`` is invalid and does not
            mean "unlimited" (SG-R-LIM-06).
        disable_ratio_limit: the one named opt-out for the ratio check. It cannot
            be combined with ``max_ratio`` (SG-R-LIM-04).

    Raises:
        InvalidLimitsError: if any value is invalid.
    """

    max_output: int | None = None  # required: None is refused in __post_init__
    max_layers: int | None = None
    max_ratio: int | None = None
    ratio_grace: int | None = None
    max_input: int | None = None
    disable_ratio_limit: bool = False

    def __post_init__(self) -> None:
        if self.max_output is None:
            raise InvalidLimitsError(
                "max_output is required (it has no default and no unlimited value)"
            )
        _integer("max_output", self.max_output, 1, _MAX_INT64)
        if self.max_layers is not None:
            _integer("max_layers", self.max_layers, 1, HARD_MAX_LAYERS)
        if self.max_ratio is not None:
            _integer("max_ratio", self.max_ratio, 1, HARD_MAX_RATIO)
        if self.ratio_grace is not None:
            _integer("ratio_grace", self.ratio_grace, 0, _MAX_INT64)
        if self.max_input is not None:
            _integer("max_input", self.max_input, 1, _MAX_INT64)
        if not isinstance(self.disable_ratio_limit, bool):
            raise InvalidLimitsError("disable_ratio_limit must be a bool")
        if self.disable_ratio_limit and self.max_ratio is not None:
            raise InvalidLimitsError("max_ratio contradicts disable_ratio_limit; set only one")


@dataclass(frozen=True, slots=True)
class EffectiveLimits:
    """The limits with defaults filled in. ``max_ratio`` 0 means the check is off."""

    max_output: int
    max_layers: int
    max_ratio: int
    ratio_grace: int
    max_input: int  # 0 means no cap

    @classmethod
    def of(cls, limits: Limits) -> EffectiveLimits:
        if limits.disable_ratio_limit:
            ratio = 0
        else:
            ratio = DEFAULT_MAX_RATIO if limits.max_ratio is None else limits.max_ratio
        assert limits.max_output is not None  # validated by Limits
        return cls(
            max_output=limits.max_output,
            max_layers=DEFAULT_MAX_LAYERS if limits.max_layers is None else limits.max_layers,
            max_ratio=ratio,
            ratio_grace=DEFAULT_RATIO_GRACE if limits.ratio_grace is None else limits.ratio_grace,
            max_input=0 if limits.max_input is None else limits.max_input,
        )

    def ratio_exceeded(self, produced: int, consumed: int) -> bool:
        """SG-R-RAT-01: ``produced > max_ratio * max(consumed, 1)`` past the grace.

        Python integers do not overflow, so the product is exact.
        """
        if self.max_ratio == 0 or produced <= self.ratio_grace:
            return False
        return produced > self.max_ratio * max(consumed, 1)
