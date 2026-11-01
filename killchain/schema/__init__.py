"""Read a log file of any security product: format detection, schema mapping and the generic parser.

Public API (docs/schema.md):

    fmt, mapping, report = schema.prepare(input, run_dir, no_llm=False)   # writes run_dir/schema.yaml + report
    stats = schema.parse(input, parsed_dir, mapping)                     # parsed_dir/firewall/part-*.parquet

`parse` sends FortiGate input to the existing parser (killchain.parser, unchanged) and everything else to
the generic parser, which writes the same Parquet layout and columns (canonical.SCHEMA), so
`db --prepare`, detect and every later stage run unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .prepare import SchemaError, load_mapping, plain_input, prepare

__all__ = ["prepare", "parse", "load_mapping", "plain_input", "SchemaError", "is_fortigate_mapping"]


def is_fortigate_mapping(mapping: Dict[str, Any]) -> bool:
    return mapping.get("format") == "fortigate"


def parse(input: Union[str, Path], out_dir: Union[str, Path], mapping: Dict[str, Any], *,
          workers: Optional[int] = None, overwrite: bool = True, quiet: bool = False, **kw: Any) -> Dict[str, Any]:
    """Parse the whole file with a fixed mapping into out_dir. Returns the parse statistics (_stats.json)."""
    out = Path(out_dir)
    plain, _ = plain_input(input)
    if is_fortigate_mapping(mapping):
        from ..parser.cli import main as fortigate_main

        args = [str(plain), "--out", str(out)] + (["--overwrite"] if overwrite else [])
        if workers:
            args += ["--workers", str(workers)]
        fortigate_main(args)
        return json.loads((out / "_stats.json").read_text(encoding="utf-8"))
    from .generic import parse_generic

    return parse_generic(plain, out, mapping, source_path=Path(input), workers=workers, overwrite=overwrite,
                         quiet=quiet, **kw)
