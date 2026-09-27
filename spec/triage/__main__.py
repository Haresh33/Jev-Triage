"""CLI:  python -m triage alert.json [--ask "question"]... [--note "context"]... [--json]
      cat alert.txt | python -m triage -

--ask   put your own question to Jev (yes/no, or pick-one with options: "Which stage? [blocked | executed | spreading]")
--note  add analyst context Jev should take into account
--json  print the full JSON result instead of the markdown report
Exit code: 0 benign, 2 malicious, 3 needs a human.
"""

from __future__ import annotations

import asyncio
import os
import sys

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from .config import Settings  # noqa: E402
from .pipeline import TriageAgent  # noqa: E402
from .report import to_markdown  # noqa: E402


def _parse(argv: list[str]) -> tuple[str | None, list[str], list[str], bool]:
    path, asks, notes, as_json = None, [], [], False
    it = iter(argv)
    for a in it:
        if a == "--json":
            as_json = True
        elif a == "--ask":
            asks.append(next(it, ""))
        elif a == "--note":
            notes.append(next(it, ""))
        elif a in ("-h", "--help"):
            return None, [], [], False
        else:
            path = a
    return path, asks, notes, as_json


async def _main(argv: list[str]) -> int:
    path, asks, notes, as_json = _parse(argv)
    if path is None:
        print(__doc__)
        return 0
    raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    agent = TriageAgent.from_settings(Settings())
    try:
        result = await agent.triage(raw, notes=notes, questions=asks, on_event=lambda m: print(f"· {m}", file=sys.stderr))
    finally:
        await agent.aclose()
    print(result.model_dump_json(indent=2) if as_json else to_markdown(result))
    return {"malicious": 2, "needs_human": 3}.get(result.verdict, 0)


def main() -> None:
    sys.exit(asyncio.run(_main(sys.argv[1:])))


if __name__ == "__main__":
    main()
