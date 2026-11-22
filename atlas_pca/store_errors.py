"""Typed failures shared by the durable stores (the reference's RangeError and the coded LedgerStoreError, BondStoreError and
BudgetLedgerError). ``code`` is stable; the message is ``"<code>: <text>"`` for the coded errors."""

__all__ = ["RangeError", "LedgerStoreError", "BondStoreError", "BudgetLedgerError", "code_of"]


class RangeError(ValueError):
    """An argument outside its range (the reference's RangeError): the caller's bug, never a store state."""

    code = "RangeError"


class _Coded(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__("%s: %s" % (code, message))
        self.code = code


class LedgerStoreError(_Coded):
    """The typed failure of every store-backed ledger operation."""


class BondStoreError(_Coded):
    """The typed failure of every store-backed bond operation."""


class BudgetLedgerError(_Coded):
    """The typed failure of the aggregate budget ledger."""


def code_of(e: BaseException) -> str:
    """The stable code of an error: its ``code`` for a coded error, ``RangeError`` for an argument error, else ``Error``."""
    return getattr(e, "code", None) if isinstance(getattr(e, "code", None), str) and isinstance(e, (_Coded, RangeError)) else "Error"
