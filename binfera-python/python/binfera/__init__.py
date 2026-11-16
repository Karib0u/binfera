"""In-process Python binding for binfera.

Load a rule set once, scan as many samples as you like::

    import binfera

    rules = binfera.Rules.from_directory("rules")
    result = binfera.analyze("sample.exe", rules)
    print(result["rules"].keys())

``analyze()`` returns upstream capa's own ``ResultDocument`` schema as a
plain ``dict`` -- the same shape ``capa -j`` prints, and the same shape
``capa.render.result_document.ResultDocument.model_validate_json`` accepts
unmodified.

The same engine reads and decompiles a binary::

    info = binfera.inspect("sample.exe")        # sections, imports, exports, details
    dec = binfera.Decompiler("sample.exe")      # needs a decompiler build: binfera.HAS_DECOMPILER
    print(dec.decompile(dec.functions[0])["text"])
"""

from ._binfera import (
    HAS_DECOMPILER,
    RULES_PIN,
    CapaError,
    CorruptFileError,
    Decompiler,
    InvalidRuleError,
    InvalidSignatureError,
    Rules,
    UnsupportedFormatError,
    __version__,
    analyze,
    decompile_all,
    diff,
    fetch_rules,
    inspect,
)

__all__ = [
    "HAS_DECOMPILER",
    "RULES_PIN",
    "CapaError",
    "CorruptFileError",
    "Decompiler",
    "InvalidRuleError",
    "InvalidSignatureError",
    "Rules",
    "UnsupportedFormatError",
    "__version__",
    "analyze",
    "decompile_all",
    "diff",
    "fetch_rules",
    "inspect",
]
