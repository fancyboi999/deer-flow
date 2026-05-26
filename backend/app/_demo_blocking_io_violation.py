"""Demo file that intentionally introduces blocking-IO candidates.

This file exists solely to demonstrate the blocking-io-comment bot. It is not
imported anywhere in the runtime and would be deleted before any real merge.

The static scanner is expected to flag every blocking call in here, and the
PR comment should surface them as "new findings" against the baseline.
"""

from __future__ import annotations

import time
from pathlib import Path


async def demo_async_handler(payload: dict) -> dict:
    """Pretends to be a request handler but blocks the event loop in two ways."""
    # 1. time.sleep inside an async function — classic event-loop killer.
    time.sleep(0.5)

    # 2. Synchronous file IO inside an async function.
    config_path = Path("/tmp/demo-config.json")
    if config_path.exists():
        contents = config_path.read_text(encoding="utf-8")
    else:
        contents = "{}"

    return {"payload": payload, "raw_config": contents}


async def demo_async_writer(name: str, data: bytes) -> None:
    """Same shape, write path — every line here is a candidate for the scanner."""
    target_dir = Path("/tmp/demo-output")
    target_dir.mkdir(parents=True, exist_ok=True)

    target = target_dir / f"{name}.bin"
    with open(target, "wb") as fh:
        fh.write(data)
