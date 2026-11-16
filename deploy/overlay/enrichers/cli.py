"""Run a local command-line tool with a timeout and return its output. Tools are installed in the image."""

import asyncio
import os
import shutil
from typing import Dict, List, Optional, Tuple


class ToolMissing(Exception):
    """The tool is not installed in this image."""


class ToolFailed(Exception):
    """The tool exited with an error or timed out."""


async def run(argv: List[str], timeout: float = 300.0, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    if shutil.which(argv[0]) is None:
        raise ToolMissing(f"{argv[0]} is not installed in this image")
    e = dict(os.environ)
    e.update(env or {})
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=e)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolFailed(f"{argv[0]} timed out after {int(timeout)}s")
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
