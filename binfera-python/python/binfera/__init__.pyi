import os
from typing import Any, Callable

__version__: str
RULES_PIN: str
HAS_DECOMPILER: bool
"""True when this build includes the native decompiler."""

class CapaError(Exception):
    """Base class for every exception this module raises."""

class InvalidRuleError(CapaError):
    """A rule file failed to parse, or the loaded rule set is invalid."""

class UnsupportedFormatError(CapaError):
    """The input format could not be auto-detected, or an explicit
    ``format=`` value is not one binfera recognizes."""

class InvalidSignatureError(CapaError):
    """A FLIRT signature file failed to parse."""

class CorruptFileError(CapaError):
    """The input bytes could not be parsed or analyzed as the selected (or
    detected) format."""

class Rules:
    """An already-parsed, already-validated rule set. Build once with
    :meth:`from_directory`, reuse across any number of :func:`analyze`
    calls."""

    @staticmethod
    def from_directory(path: str | os.PathLike[str]) -> "Rules":
        """Parse every rule file under ``path`` and build the matching rule
        set. Raises :class:`InvalidRuleError` on an unparseable rule file or
        an invalid rule set (duplicate name, missing dependency, cycle)."""

def diff(
    a: bytes | bytearray | str | os.PathLike[str],
    b: bytes | bytearray | str | os.PathLike[str],
    rules: Rules | None = None,
    *,
    jobs: int | None = None,
    format: str | None = None,
    arch: str | None = None,
    pair: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Compare two binaries and return the diff document as a ``dict``.

    :param rules: also compare capabilities when given.
    :param pair: function addresses in ``a`` and ``b``; returns that pair's
        block and instruction diff instead of the whole comparison.
    """

def analyze(
    data_or_path: bytes | bytearray | str | os.PathLike[str],
    rules: Rules,
    *,
    jobs: int | None = None,
    format: str | None = None,
    os: str | None = None,
    arch: str | None = None,
    file_only: bool = False,
) -> dict[str, Any]:
    """Run binfera's analysis pipeline and return upstream's
    ``ResultDocument`` schema as a ``dict``.

    :param data_or_path: raw sample bytes, or a path to read them from.
    :param rules: a :class:`Rules` instance built with
        :meth:`Rules.from_directory`.
    :param jobs: worker thread count; ``1`` is the single-threaded
        reference mode (default: available logical cores).
    :param format: ``"auto"`` (default), ``"pe"``, ``"elf"``, ``"sc32"``,
        ``"sc64"``, ``"freeze"``, ``"dotnet"``, or ``"macho"``.
    :param os: ``"auto"`` (default), ``"linux"``, ``"macos"``, or
        ``"windows"``.
    :param arch: sample architecture override (default: auto-detect).
    :param file_only: skip code recovery, extracting only file-scope
        features.
    :raises InvalidRuleError: from a bad rule set (raised by
        :meth:`Rules.from_directory`, not this function).
    :raises UnsupportedFormatError: the format could not be determined, or
        an unknown ``format=`` value was given.
    :raises InvalidSignatureError: a FLIRT signature file failed to parse.
    :raises CorruptFileError: the input could not be parsed or analyzed.
    """

def fetch_rules(directory: str | os.PathLike[str], ref: str | None = None) -> None:
    """Clone the pinned capa-rules release into ``directory``. Never runs
    implicitly -- not at import time, not as a side effect of
    :meth:`Rules.from_directory`. Requires ``git`` on ``PATH``."""

def inspect(
    data_or_path: bytes | bytearray | str | os.PathLike[str],
    *,
    format: str | None = None,
    arch: str | None = None,
    guess_shellcode: bool = False,
) -> dict[str, Any]:
    """Read a PE, ELF or Mach-O image's headers without recovering or decompiling code.

    Returns ``format``, ``arch``, ``entry``, ``sections``, ``regions``, ``imports``,
    ``exports``, ``details`` and ``warnings`` (the document ``binfera --image-info -j``
    prints). ``format="sc32"``/``"sc64"`` reads raw shellcode; ``guess_shellcode`` tries
    x86/x64 raw code on an input with no executable header.
    """

class Decompiler:
    """An opened image that decompiles any of its functions.

    Opening recovers the image once; each call reuses that work. Needs a build with the
    decompiler (:data:`HAS_DECOMPILER`); otherwise construction raises :class:`CapaError`.
    A session belongs to the thread that created it and holds the GIL while it works.
    """

    def __init__(
        self,
        data_or_path: bytes | bytearray | str | os.PathLike[str],
        *,
        format: str | None = None,
        arch: str | None = None,
        os: str | None = None,
    ) -> None: ...
    @property
    def functions(self) -> list[int]:
        """Addresses of the recovered functions, ascending."""
    @property
    def warnings(self) -> list[str]:
        """File-wide diagnostics gathered while opening the image."""
    def set_limits(
        self,
        *,
        timeout_ms: int | None = None,
        max_instructions: int | None = None,
        max_work: int | None = None,
    ) -> None:
        """Replace the resource limits (defaults 10000 ms, 10000 instructions, 20000000 work)."""
    def decompile(self, address: int) -> dict[str, Any]:
        """Decompile the function at ``address``.

        Keys: ``text``, ``name``, ``calling_convention``, ``warnings``, ``notes``,
        ``incomplete``, ``unknown_callees``, ``lines`` (instruction addresses behind each
        line of ``text``), ``frame`` (stack symbols), ``timings``, ``file_warnings``.
        """
    def unit(self, addresses: list[int]) -> dict[str, Any]:
        """Decompile functions into one self-contained C translation unit.

        Keys: ``text``, ``functions``, ``guesses``, ``rewrites``, ``unrewritten``,
        ``unresolved_types``, ``file_warnings``. A function that fails fails the unit.
        """

def decompile_all(
    data_or_path: bytes | bytearray | str | os.PathLike[str],
    *,
    format: str | None = None,
    arch: str | None = None,
    os: str | None = None,
    shard: tuple[int, int] | None = None,
    on_event: Callable[[dict[str, Any]], object] | None = None,
) -> list[dict[str, Any]] | None:
    """Decompile every recovered function.

    Returns the event records ``binfera --decompile-all`` prints: a ``start`` record listing
    the functions and supplied ``names``, ``function`` records (text, assembly, graph, calls),
    then ``settled`` before deferred resource retries and ``done`` at completion. A later
    function record replaces an earlier ``retry_pending`` record for the same address. With ``on_event`` each record is passed to it as it completes and the call
    returns ``None``; an exception from the callback stops the run and propagates.
    ``shard=(index, count)`` decompiles one round-robin share.
    """
